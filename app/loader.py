"""Materialize a sealed evidence set into lazily parsed indexes.

Both certificates and revocation objects stay lazy:

* certificates are parsed only when graph search reaches them (the
  acceptance load has 100k certs but adjudicates a handful of leaves);
* CRL/OCSP objects are not fully parsed up front either.  A zero-crypto
  scope header (issuer Name, AKI, IDP scope, delta linkage, response
  serials) is extracted once at seal time into a sidecar, so a fresh
  process adjudicating a small chain never reads or parses unrelated
  revocation DER — e.g. dozens of CRLs archived for an unrelated CA.

Only revocation evidence whose scope relates to a certificate actually
reached by path construction (issuer Name/AKI, distribution point or an
OCSP CertID serial) is materialized with the full cryptographic parser.
"""
from __future__ import annotations

import base64
import json
import os

from . import evidence as ev
from .certmodel import ParsedCert, parse_certificate
from .errors import MalformedEvidenceError, UnsupportedError
from .graph import CertGraph


class LoadedSet:
    def __init__(self, store, manifest: dict):
        self.store = store
        self.manifest = manifest
        self.content = manifest["content"]
        self._parsed: dict[str, ParsedCert] = {}
        self.crls: dict[str, ev.CrlObject] = {}
        self.ocsps: dict[str, ev.OcspObject] = {}
        # Fully-parsed objects that were structurally/profile rejected.
        self._crl_rejected: set[str] = set()
        self._ocsp_rejected: set[str] = set()
        # Cheap scope descriptors (digest -> scope), sorted lists derived.
        self._crl_scopes: dict[str, ev.CrlScope] = {}
        self._ocsp_scopes: dict[str, ev.OcspScope] = {}
        self._scopes_loaded = False
        self.parse_problems: list[dict] = []

    @classmethod
    def from_store(cls, store, manifest: dict) -> "LoadedSet":
        return cls(store, manifest)

    def get_blob(self, digest: str) -> bytes:
        return self.store.get_blob(digest)

    # -------------------------------------------------------- certificates
    def cert(self, digest: str) -> ParsedCert | None:
        if digest in self._parsed:
            return self._parsed[digest]
        try:
            data = self.get_blob(digest)
            pc = parse_certificate(data)
        except (UnsupportedError, MalformedEvidenceError) as exc:
            self._parsed[digest] = None  # type: ignore[assignment]
            self.parse_problems.append({
                "sha256": digest, "kind": "certificate",
                "code": exc.code, "message": exc.message, "detail": exc.detail})
            return None
        self._parsed[digest] = pc
        return pc

    def all_cert_digests(self) -> list[str]:
        return list(self.content["certificates"])

    def build_graph(self, anchor_digests: set[str]) -> CertGraph:
        """Parse only anchor certs eagerly; everything else stays lazy."""
        certs: dict[str, ParsedCert] = {}
        for d in anchor_digests:
            pc = self.cert(d)
            if pc is not None:
                certs[d] = pc

        class LazyGraph(CertGraph):
            def __init__(self_inner, loader, anchor_ds):
                self_inner.loader = loader
                self_inner.anchor_ds = anchor_ds
                self_inner.certs = certs
                self_inner.by_name = {}
                self_inner.by_name_key = {}
                self_inner._edge_cache = {}

            def _materialize(self_inner, digest: str) -> ParsedCert | None:
                if digest in self_inner.certs:
                    return self_inner.certs[digest]
                pc = self_inner.loader.cert(digest)
                if pc is None:
                    return None
                self_inner.certs[digest] = pc
                self_inner.by_name.setdefault(pc.subject_der, []).append(digest)
                self_inner.by_name_key.setdefault(
                    (pc.subject_der, pc.spki_bitstring), []).append(digest)
                return pc

            def get_cert(self_inner, digest: str) -> ParsedCert | None:
                return self_inner._materialize(digest)

        graph = LazyGraph(self, anchor_digests)

        # Override candidate lookup to lazily parse: find certs whose SUBJECT
        # equals child's issuer DN. That needs an index by subject name, so we
        # build name buckets from raw DER cheaply using cached ParsedCert where
        # available, parsing only issuers reachable by name. To find issuers by
        # name without parsing all certificates, maintain a precomputed name
        # index (built during ingestion; see store detail). Fallback: parse all
        # when the index is absent (older stores).
        index = self._subject_name_index()
        graph._subject_index = index

        def candidate_issuers(child_fp: str) -> list[str]:
            child = graph.certs.get(child_fp) or self.cert(child_fp)
            if child is None:
                return []
            digests = index.get(child.issuer_der, [])
            out = []
            for d in digests:
                pc = graph._materialize(d)
                if pc is not None:
                    out.append(d)
            return sorted(out)

        graph.candidate_issuers = candidate_issuers  # type: ignore[assignment]

        # by_issuer used by revocation engine: resolve by name + AKI.
        def by_issuer(name_der, aki):
            res = []
            for d in index.get(name_der, []):
                pc = graph._materialize(d)
                if pc is None:
                    continue
                if aki is not None and pc.ski is not None and pc.ski != aki:
                    continue
                res.append(pc)
            return res

        graph.by_issuer = by_issuer  # type: ignore[assignment]
        return graph

    def _subject_name_index(self) -> dict[bytes, list[str]]:
        """Use the cheap index materialized at seal time (raw Name DER keys,
        base64 encoded in the sidecar file)."""
        cached = getattr(self, "_name_idx", None)
        if cached is not None:
            return cached
        idx_path = self._name_index_path()
        idx: dict[bytes, list[str]] = {}
        if os.path.exists(idx_path):
            with open(idx_path) as f:
                raw_index = json.load(f)
            for name_b64, digests in raw_index.items():
                idx[base64.b64decode(name_b64)] = digests
        else:
            # Slow fallback for stores sealed before sidecars existed.
            for d in self.content["certificates"]:
                pc = self.cert(d)
                if pc is not None:
                    idx.setdefault(pc.subject_der, []).append(d)
        self._name_idx = idx
        return idx

    def _name_index_path(self) -> str:
        return os.path.join(self.store.root, "packages",
                            f"{self.manifest['evidence_set_id']}.nameindex.json")

    # --------------------------------------------------------- revocation
    def _earliest_received(self, items) -> dict[str, int]:
        # Identical bytes archived multiple times: evidence is possessed at
        # the earliest recorded received_at.
        m: dict[str, int] = {}
        for item in items:
            d, r = item["sha256"], item["received_at"]
            m[d] = r if d not in m else min(m[d], r)
        return m

    def _rev_index_path(self) -> str:
        return os.path.join(self.store.root, "packages",
                            f"{self.manifest['evidence_set_id']}.revindex.json")

    def load_revocation(self) -> None:
        """Populate cheap scope descriptors without parsing any DER.

        Uses the seal-time sidecar when present (no blob reads at all for
        unrelated evidence); otherwise falls back to a zero-crypto header
        scan over the raw DER (older stores / offline packages).
        """
        if self._scopes_loaded:
            return
        crl_received = self._earliest_received(self.content["crls"])
        ocsp_received = self._earliest_received(self.content["ocsps"])
        sidecar = self._read_rev_sidecar()
        if sidecar is not None:
            for digest, header_raw in sidecar.get("crls", {}).items():
                if digest not in crl_received:
                    continue
                header = self._crl_header_from_json(header_raw)
                self._crl_scopes[digest] = ev.CrlScope(
                    digest, crl_received[digest], header)
            for digest, serials in sidecar.get("ocsps", {}).items():
                if digest not in ocsp_received:
                    continue
                self._ocsp_scopes[digest] = ev.OcspScope(
                    digest, ocsp_received[digest],
                    frozenset(serials) if serials is not None else None)
        else:
            for digest, received_at in crl_received.items():
                header = None
                try:
                    header = ev.crl_scope_header(self.get_blob(digest))
                except MalformedEvidenceError:
                    header = None
                self._crl_scopes[digest] = ev.CrlScope(digest, received_at, header)
            for digest, received_at in ocsp_received.items():
                serials = None
                try:
                    serials = frozenset(ev.ocsp_scope_serials(self.get_blob(digest)))
                except (MalformedEvidenceError, UnsupportedError):
                    serials = None
                self._ocsp_scopes[digest] = ev.OcspScope(digest, received_at, serials)

        # Defensive: sidecar could only be older than the manifest; make sure
        # every manifest object has a descriptor even if the sidecar missed it.
        for digest, received_at in crl_received.items():
            self._crl_scopes.setdefault(
                digest, ev.CrlScope(digest, received_at, None))
        for digest, received_at in ocsp_received.items():
            self._ocsp_scopes.setdefault(
                digest, ev.OcspScope(digest, received_at, None))
        self._scopes_loaded = True

    def _read_rev_sidecar(self) -> dict | None:
        path = self._rev_index_path()
        if not path or not os.path.exists(path):
            return None
        with open(path) as f:
            return json.load(f)

    @staticmethod
    def _crl_header_from_json(raw: dict | None) -> dict | None:
        if raw is None:
            return None
        return {
            "issuer_der": base64.b64decode(raw["issuer_der_b64"]),
            "aki": (base64.b64decode(raw["aki_b64"])
                    if raw.get("aki_b64") is not None else None),
            "crl_number": raw["crl_number"],
            "base_crl_number": raw["base_crl_number"],
            "idp_uris": tuple(raw["idp_uris"]),
            "only_user_certs": raw["only_user_certs"],
            "only_ca_certs": raw["only_ca_certs"],
            "entry_count": raw["entry_count"],
        }

    def crl_scopes(self) -> list[ev.CrlScope]:
        self.load_revocation()
        return [self._crl_scopes[d] for d in sorted(self._crl_scopes)]

    def ocsp_scopes(self) -> list[ev.OcspScope]:
        self.load_revocation()
        return [self._ocsp_scopes[d] for d in sorted(self._ocsp_scopes)]

    def materialize_crl(self, scope: ev.CrlScope) -> ev.CrlObject | None:
        """Full parse of one in-scope CRL (cached per adjudication)."""
        digest = scope.fingerprint
        if digest in self.crls:
            return self.crls[digest]
        if digest in self._crl_rejected:
            return None
        try:
            obj = ev.parse_crl(self.get_blob(digest), scope.received_at)
        except (UnsupportedError, MalformedEvidenceError) as exc:
            self._crl_rejected.add(digest)
            self.parse_problems.append({
                "sha256": digest, "kind": "crl",
                "code": exc.code, "message": exc.message, "detail": exc.detail})
            return None
        self.crls[digest] = obj
        return obj

    def materialize_ocsp(self, scope: ev.OcspScope) -> ev.OcspObject | None:
        """Full parse of one in-scope OCSP response (cached per adjudication)."""
        digest = scope.fingerprint
        if digest in self.ocsps:
            return self.ocsps[digest]
        if digest in self._ocsp_rejected:
            return None
        try:
            obj = ev.parse_ocsp(self.get_blob(digest), scope.received_at)
        except (UnsupportedError, MalformedEvidenceError) as exc:
            self._ocsp_rejected.add(digest)
            self.parse_problems.append({
                "sha256": digest, "kind": "ocsp",
                "code": exc.code, "message": exc.message, "detail": exc.detail})
            return None
        self.ocsps[digest] = obj
        return obj
