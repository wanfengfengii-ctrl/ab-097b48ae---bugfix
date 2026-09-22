"""Materialize a sealed evidence set into lazily parsed indexes.

Both certificates and revocation objects are parsed *lazily and only when
they can concern the certificate under adjudication*:

* certificates are parsed on first access (the acceptance load has 100k certs
  but adjudicates a handful of leaves);
* CRLs are fully DER-parsed only when their issuer Name and AKI match a
  certificate whose revocation is being evaluated, and OCSP responses only
  when they carry a CertID for that certificate's serial.

At seal time every revocation object is fully parsed exactly once (seal
already x509-loads every CRL for the entry-count limit), and the resulting
scope (CRL issuer Name/AKI; OCSP CertID serials) plus the in/out-of-profile
verdict is stored in a sidecar index. A cold process therefore bounds scope
from the sidecar and never even reads an unrelated revocation DER after a
restart, instance switch or adjudication-cache miss. Richer checks (IDP
distribution point, onlyContains, certID hashes, signatures, validity
windows) still run through the full parser during adjudication, so verdicts
and evidence dispositions are identical to eager parsing. If the sidecar is
absent or does not exactly cover the sealed universe (stores sealed before
sidecars, or the offline package verifier), the loader falls back to exact
eager parsing.
"""
from __future__ import annotations

import base64
import json
import os

from . import evidence as ev
from . import metrics as _metrics
from .certmodel import ParsedCert, parse_certificate
from .errors import MalformedEvidenceError, UnsupportedError
from .graph import CertGraph

REV_INDEX_VERSION = 1


class LoadedSet:
    def __init__(self, store, manifest: dict):
        self.store = store
        self.manifest = manifest
        self.content = manifest["content"]
        self._parsed: dict[str, ParsedCert] = {}
        self.crls: dict[str, ev.CrlObject] = {}
        self.ocsps: dict[str, ev.OcspObject] = {}
        self.parse_problems: list[dict] = []
        # Lazily materialized revocation objects (None == failed to parse).
        self._crl_cache: dict[str, ev.CrlObject | None] = {}
        self._ocsp_cache: dict[str, ev.OcspObject | None] = {}
        self._rev_index_loaded = False
        # issuer Name DER -> [(digest, aki|None)]; serial -> [digest]
        self._crl_by_issuer: dict[bytes, list[tuple[str, bytes | None]]] = {}
        self._ocsp_by_serial: dict[int, list[str]] = {}
        self._crl_received: dict[str, int] = {}
        self._ocsp_received: dict[str, int] = {}

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
    def _ensure_revocation_index(self) -> None:
        if self._rev_index_loaded:
            return
        self._crl_received = {x["sha256"]: x["received_at"]
                              for x in self.content.get("crls", [])}
        self._ocsp_received = {x["sha256"]: x["received_at"]
                               for x in self.content.get("ocsps", [])}
        sidecar = self._load_rev_index_sidecar()
        if sidecar is not None and self._sidecar_covers_universe(sidecar):
            try:
                self._apply_rev_sidecar(sidecar)
            except Exception:
                # Corrupt row content: reset and use the exact eager path.
                self._crl_by_issuer = {}
                self._ocsp_by_serial = {}
                self._build_rev_index_from_blobs()
        else:
            # Missing/stale/partial sidecar (stores sealed before sidecars
            # existed, or offline package review): exact eager parse, which
            # reproduces the original dispositions byte-for-byte.
            self._build_rev_index_from_blobs()
        for v in self._crl_by_issuer.values():
            v.sort()
        for v in self._ocsp_by_serial.values():
            v.sort()
        self._rev_index_loaded = True

    def _apply_rev_sidecar(self, sidecar: dict) -> None:
        for row in sidecar.get("crls", []):
            digest = row["s"]
            if digest not in self._crl_received:
                continue
            if row.get("e"):
                # Seal-time full parse already rejected this object; carry
                # the verdict forward without touching the blob.
                self._record_rev_problem("crl", digest, row.get("p"))
                continue
            aki = base64.b64decode(row["a"]) if row.get("a") else None
            self._crl_by_issuer.setdefault(
                base64.b64decode(row["i"]), []).append((digest, aki))
        for row in sidecar.get("ocsps", []):
            digest = row["s"]
            if digest not in self._ocsp_received:
                continue
            if row.get("e"):
                self._record_rev_problem("ocsp", digest, row.get("p"))
                continue
            for serial in row["n"]:
                self._ocsp_by_serial.setdefault(serial, []).append(digest)

    def _sidecar_covers_universe(self, sidecar: dict) -> bool:
        """The sidecar must enumerate exactly the sealed CRL/OCSP universe;
        otherwise scope filtering could silently hide an object's disposition.
        Any mismatch forces the exact eager blob path."""
        try:
            side_crls = {r["s"] for r in sidecar.get("crls", [])}
            side_ocsps = {r["s"] for r in sidecar.get("ocsps", [])}
        except (TypeError, KeyError):
            return False
        return (side_crls == set(self._crl_received)
                and side_ocsps == set(self._ocsp_received))

    def _record_rev_problem(self, kind: str, digest: str,
                            problem: dict | None) -> None:
        if any(p["sha256"] == digest and p["kind"] == kind
               for p in self.parse_problems):
            (self._crl_cache if kind == "crl" else self._ocsp_cache)[digest] = None
            return
        problem = problem or {}
        self.parse_problems.append({
            "sha256": digest, "kind": kind,
            "code": problem.get("code", "MALFORMED_EVIDENCE"),
            "message": problem.get("message", ""),
            "detail": problem.get("detail", {})})
        # Mark cached as failed so on-demand access never re-reads the blob.
        (self._crl_cache if kind == "crl" else self._ocsp_cache)[digest] = None

    def _rev_index_path(self) -> str:
        return os.path.join(self.store.root, "packages",
                            f"{self.manifest['evidence_set_id']}.revindex.json")

    def _load_rev_index_sidecar(self) -> dict | None:
        path = self._rev_index_path()
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            return None
        if data.get("version") != REV_INDEX_VERSION:
            return None
        return data

    def _build_rev_index_from_blobs(self) -> None:
        """Fallback for stores sealed before revocation sidecars existed and
        for offline package review: fully parse every revocation object via
        the same on-demand path, exactly reproducing the eager loader's scope
        index and parse-rejection dispositions (these paths stay
        byte-identical). The sealed content lists are SHA-sorted, so the
        resulting parse-problem order is deterministic."""
        for digest in self._crl_received:
            obj = self.get_crl(digest)
            if obj is not None:
                self._crl_by_issuer.setdefault(obj.issuer_der, []).append(
                    (digest, obj.aki))
        for digest in self._ocsp_received:
            obj = self.get_ocsp(digest)
            if obj is not None:
                for serial in obj.responses:
                    self._ocsp_by_serial.setdefault(serial, []).append(digest)

    def get_crl(self, digest: str) -> ev.CrlObject | None:
        """Fully parse one CRL on demand; failures are recorded once."""
        if digest in self._crl_cache:
            return self._crl_cache[digest]
        try:
            raw = self.get_blob(digest)
            obj = ev.parse_crl(raw, self._crl_received[digest])
        except (UnsupportedError, MalformedEvidenceError) as exc:
            self._crl_cache[digest] = None
            self.parse_problems.append({
                "sha256": digest, "kind": "crl",
                "code": exc.code, "message": exc.message, "detail": exc.detail})
            return None
        except KeyError:
            self._crl_cache[digest] = None
            return None
        self._crl_cache[digest] = obj
        self.crls[digest] = obj
        _metrics.record_parsed(self.manifest["evidence_set_id"], "crl", digest)
        return obj

    def get_ocsp(self, digest: str) -> ev.OcspObject | None:
        """Fully parse one OCSP response on demand; failures recorded once."""
        if digest in self._ocsp_cache:
            return self._ocsp_cache[digest]
        try:
            raw = self.get_blob(digest)
            obj = ev.parse_ocsp(raw, self._ocsp_received[digest])
        except (UnsupportedError, MalformedEvidenceError) as exc:
            self._ocsp_cache[digest] = None
            self.parse_problems.append({
                "sha256": digest, "kind": "ocsp",
                "code": exc.code, "message": exc.message, "detail": exc.detail})
            return None
        except KeyError:
            self._ocsp_cache[digest] = None
            return None
        self._ocsp_cache[digest] = obj
        self.ocsps[digest] = obj
        _metrics.record_parsed(self.manifest["evidence_set_id"], "ocsp", digest)
        return obj

    def crl_candidates_for(self, cert: ParsedCert) -> list[ev.CrlObject]:
        """CRLs whose issuer Name/AKI can cover ``cert`` — the exact pre-filter
        the revocation engine applies before scope/signature/window checks."""
        self._ensure_revocation_index()
        out: list[ev.CrlObject] = []
        seen: set[str] = set()
        for digest, aki in self._crl_by_issuer.get(cert.issuer_der, []):
            if digest in seen:
                continue
            seen.add(digest)
            if aki is not None and cert.aki is not None and aki != cert.aki:
                continue
            obj = self.get_crl(digest)
            if obj is not None:
                out.append(obj)
        return out

    def ocsp_candidates_for(self, cert: ParsedCert) -> list[ev.OcspObject]:
        """OCSP responses carrying a single response for ``cert``'s serial."""
        self._ensure_revocation_index()
        out: list[ev.OcspObject] = []
        for digest in self._ocsp_by_serial.get(cert.serial, []):
            obj = self.get_ocsp(digest)
            if obj is not None:
                out.append(obj)
        return out

    def load_revocation(self) -> None:
        """Materialize the cheap scope index. Revocation objects themselves
        are parsed lazily through
        :meth:`crl_candidates_for`/`ocsp_candidates_for`."""
        self._ensure_revocation_index()
