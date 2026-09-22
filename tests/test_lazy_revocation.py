"""Lazy, scope-driven revocation materialization.

A sealed set may carry up to 2,000 CRL/OCSP objects; adjudicating a handful
of certificates must never fully DER-parse unrelated archived revocation
evidence, even in a cold process (restart / other API instance / uncached
adjudication). These tests also pin the unchanged rich semantics:
base/delta selection, IDP distribution-point scope, OCSP routing, parse
rejection and the resource cap.
"""
import hashlib
import os
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app import evidence as ev
from app import metrics
from app.adjudge import adjudicate
from app.certmodel import fp_of
from app.errors import ConflictError
from app.package import build_package
from app.storage import Store
from verify.verify_package import verify_package

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000


def _chain():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    return rk, ck, lk, root, ca, leaf


def _request(leaf, root_fp, lk, artifact=b"artifact", signed=SIGNED):
    d = hashlib.sha256(artifact).digest()
    s = lk.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
    return {"artifact_digest": d.hex(), "signature": s.hex(),
            "signature_algorithm": "1.2.840.10045.4.3.2", "signed_at": signed,
            "knowledge_cutoff": CUTOFF,
            "leaf_certificate_sha256": fp_of(pf.der(leaf)),
            "initial_policies": [ANY], "trust_anchors": [root_fp]}


class SetBuilder:
    def __init__(self, store, sid):
        self.store = store
        self.sid = sid
        store.create_set(sid, "c")
        self.rows = []

    def cert(self, c, ref=None):
        d = pf.der(c)
        self.store.put_blob(d)
        self.rows.append({"client_ref": ref or "c" + fp_of(d)[:16],
                          "kind": "certificate", "content_sha256": fp_of(d),
                          "received_at": RECEIVED})

    def rev(self, o, ref, kind="crl"):
        d = pf.der(o)
        self.store.put_blob(d)
        self.rows.append({"client_ref": ref, "kind": kind,
                          "content_sha256": fp_of(d),
                          "received_at": RECEIVED})
        return fp_of(d)

    def seal(self):
        self.store.add_items(self.sid, self.rows)
        return self.store.seal(self.sid)


# ------------------------------------------------------------- seal scopes
def test_crl_seal_scope_matches_full_parser():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    ca = pf.build_cert("C", None, rk, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       self_signed=True)
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    cases = [
        pf.build_crl(ca, ck, [(leaf.serial_number, SIGNED - 10, "key_compromise")],
                     last_update=SIGNED - 100, next_update=SIGNED + 100,
                     crl_number=2),
        pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                     next_update=SIGNED + 100, crl_number=3, delta_of=2),
        pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                     next_update=SIGNED + 100, crl_number=1,
                     idp_uris=("http://ca.test/a.crl",)),
        pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                     next_update=SIGNED + 100, crl_number=1, only_user=True),
        pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                     next_update=SIGNED + 100, crl_number=1, only_ca=True),
        pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                     next_update=SIGNED + 100, crl_number=1, akify=False),
    ]
    for obj in cases:
        raw = pf.der(obj)
        parsed, problem = ev.review_crl(raw, RECEIVED)
        assert problem is None
        scope = ev.crl_scope_from_obj(parsed)
        full = ev.parse_crl(raw, RECEIVED)
        assert scope.issuer_name == full.issuer_der
        assert scope.aki == full.aki


def test_ocsp_seal_scope_matches_full_parser():
    from cryptography.hazmat.primitives import hashes as H

    rk, ck, lk, dk = pf.gen_key(), pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    deleg = pf.build_cert("D", ca, dk, ck, key_usage=("digitalSignature",),
                          eku=("ocspSigning",), policies=[ANY])
    for hash_alg in (H.SHA1(), H.SHA256(), H.SHA384(), H.SHA512()):
        oc = pf.build_ocsp(leaf, ca, ck, "good", this_update=SIGNED - 100,
                           next_update=SIGNED + 100, hash_alg=hash_alg)
        raw = pf.der(oc)
        parsed, problem = ev.review_ocsp(raw, RECEIVED)
        assert problem is None
        scope = ev.ocsp_scope_from_obj(parsed)
        full = ev.parse_ocsp(raw, RECEIVED)
        assert set(scope.serials) == set(full.responses)
        assert leaf.serial_number in scope.serials
    # Delegated responder responses parse and scope too.
    od = pf.build_ocsp(leaf, ca, ck, "good", this_update=SIGNED - 100,
                       next_update=SIGNED + 100, responder_key=dk,
                       responder_cert=deleg, hash_alg=H.SHA256())
    parsed, problem = ev.review_ocsp(pf.der(od), RECEIVED)
    assert problem is None and leaf.serial_number in \
        ev.ocsp_scope_from_obj(parsed).serials


def test_seal_review_records_out_of_profile_object():
    # An indirect CRL loads as x509 but the full profile parse rejects it
    # (UNSUPPORTED); review_crl surfaces that exact verdict so the seal-time
    # index records parse rejection without any later blob read.
    rk, ck = pf.gen_key(), pf.gen_key()
    ca = pf.build_cert("C", None, rk, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       self_signed=True)
    indirect = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                            next_update=SIGNED + 100, crl_number=1,
                            indirect=True)
    obj, problem = ev.review_crl(pf.der(indirect), RECEIVED)
    assert obj is None
    assert problem["code"] == "UNSUPPORTED"
    # A healthy CRL still yields no problem.
    good = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    obj2, problem2 = ev.review_crl(pf.der(good), RECEIVED)
    assert obj2 is not None and problem2 is None


# ------------------------------------------------------------- lazy behavior
def _build_noise_set(store_path, n_noise=48):
    store = Store(store_path)
    sid = "es_lazy_00000000000000000000000000001"
    b = SetBuilder(store, sid)
    rk, ck, lk, root, ca, leaf = _chain()
    # Target base CRL plus a fresher delta (base/delta selection semantics).
    base = pf.build_crl(ca, ck, [], last_update=SIGNED - 1_000,
                        next_update=SIGNED + 1_000, crl_number=10)
    delta = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                         next_update=SIGNED + 1_000, crl_number=11, delta_of=10)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 1_000,
                        next_update=SIGNED + 1_000, crl_number=1)
    for c in (root, ca, leaf):
        b.cert(c)
    target = {b.rev(base, "base"), b.rev(delta, "delta"), b.rev(rcrl, "rootcrl")}
    # Unrelated Noise CA + n_noise legal GOOD CRLs.
    nk = pf.gen_key()
    noise = pf.build_cert("Noise CA", None, nk, nk, is_ca=True,
                          key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                          self_signed=True)
    b.cert(noise, "noise-ca")
    noise_fps = set()
    for i in range(n_noise):
        o = pf.build_crl(noise, nk, [], last_update=SIGNED - 500 + i,
                         next_update=SIGNED + 50_000 + i, crl_number=i + 1)
        noise_fps.add(b.rev(o, f"noise-{i}"))
    manifest = b.seal()
    store.close()
    return sid, (rk, ck, lk, root, ca, leaf), target, noise_fps, manifest


def test_unrelated_crls_never_materialized_cold(tmp_path):
    data = str(tmp_path / "data")
    sid, keys, target, noise_fps, _ = _build_noise_set(data)
    rk, ck, lk, root, ca, leaf = keys

    # Cold restart: a brand-new Store/process view of the sealed volume.
    store = Store(data)
    read = set()
    orig = Store.get_blob

    def traced(self, digest):
        read.add(digest)
        return orig(self, digest)

    metrics.reset()
    Store.get_blob = traced
    try:
        res = adjudicate(store, sid,
                         _request(leaf, fp_of(pf.der(root)), lk))
    finally:
        Store.get_blob = orig
    assert res["verdict"]["status"] == "VALID"
    sel = res["revocation_results"][0]["selected_evidence"]
    assert sel["kind"] == "crl"  # delta merged onto base
    # No unrelated revocation DER is even read from the blob store.
    assert not (read & noise_fps)
    # Only in-scope target CRLs are fully parsed.
    parsed = set(metrics.snapshot()[sid]["crl_full_parsed"])
    assert parsed <= target and parsed
    assert not (parsed & noise_fps)
    store.close()


def test_uncached_second_adjudication_skips_noise(tmp_path):
    data = str(tmp_path / "data")
    sid, keys, target, noise_fps, _ = _build_noise_set(data)
    rk, ck, lk, root, ca, leaf = keys

    store = Store(data)
    read = set()
    orig = Store.get_blob

    def traced(self, digest):
        read.add(digest)
        return orig(self, digest)

    metrics.reset()
    Store.get_blob = traced
    try:
        r1 = adjudicate(store, sid,
                        _request(leaf, fp_of(pf.der(root)), lk, artifact=b"one"))
        read.clear()
        # New request digest (different artifact/signed_at) => cache miss.
        r2 = adjudicate(
            store, sid,
            _request(leaf, fp_of(pf.der(root)), lk, artifact=b"two",
                     signed=SIGNED + 10))
    finally:
        Store.get_blob = orig
    assert r1["verdict"]["status"] == "VALID"
    assert r2["verdict"]["status"] == "VALID"
    assert not (read & noise_fps)
    store.close()


def test_noise_package_offline_review_byte_identical(tmp_path):
    data = str(tmp_path / "data")
    sid, keys, target, noise_fps, manifest = _build_noise_set(data)
    rk, ck, lk, root, ca, leaf = keys
    store = Store(data)
    res = adjudicate(store, sid, _request(leaf, fp_of(pf.der(root)), lk))
    pkg = build_package(store, res, manifest)
    path = tmp_path / "pkg.zip"
    path.write_bytes(pkg)
    report = verify_package(str(path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
    # The package still archives the whole CRL universe...
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(pkg)) as zf:
        bundled = {n.split("/")[-1].removesuffix(".der")
                   for n in zf.namelist() if n.startswith("der/crls/")}
    assert bundled == target | noise_fps
    # ...but the result only ever considered the in-scope target CRLs.
    considered = set()
    for snap in res["revocation_snapshot"]:
        for c in snap["considered_evidence"]:
            considered.add(c["fingerprint"])
    assert not (considered & noise_fps)
    store.close()


def test_unrelated_ocsp_never_materialized(tmp_path):
    store = Store(str(tmp_path / "data"))
    sid = "es_lazy_ocsp_0000000000000000000000001"
    b = SetBuilder(store, sid)
    rk, ck, lk, root, ca, leaf = _chain()
    for c in (root, ca, leaf):
        b.cert(c)
    b.rev(pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1), "crl")
    b.rev(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1), "rcrl")
    # GOOD OCSP for the target leaf (routed and used).
    target_oc = pf.build_ocsp(leaf, ca, ck, "good", this_update=SIGNED - 100,
                              next_update=SIGNED + 100,
                              hash_alg=hashes.SHA256())
    target_fp = b.rev(target_oc, "ocsp-leaf", kind="ocsp")
    # Noise OCSP responses answering only foreign (unrelated) serials.
    noise_fps = set()
    for i in range(10):
        oc = _noise_ocsp(ca, ck, 1_000_000 + i)
        noise_fps.add(b.rev(oc, f"ocsp-{i}", kind="ocsp"))
    b.seal()

    store2 = Store(str(tmp_path / "data"))  # cold restart
    read = set()
    orig = Store.get_blob

    def traced(self, digest):
        read.add(digest)
        return orig(self, digest)

    metrics.reset()
    Store.get_blob = traced
    try:
        res = adjudicate(store2, sid,
                         _request(leaf, fp_of(pf.der(root)), lk))
    finally:
        Store.get_blob = orig
    assert res["verdict"]["status"] == "VALID"
    assert res["revocation_results"][0]["selected_evidence"]["kind"] == "ocsp"
    assert not (read & noise_fps)
    parsed = set(metrics.snapshot()[sid]["ocsp_full_parsed"])
    assert parsed == {target_fp}
    store.close()
    store2.close()


def _noise_ocsp(ca, ca_key, foreign_serial):
    """OCSP GOOD response for a throwaway certificate with a foreign serial
    (same CA name/key CertID, serial never present in the evidence set)."""
    fk = pf.gen_key()
    throwaway = pf.build_cert(
        "foreign-holder", ca, fk, ca_key, serial=foreign_serial,
        key_usage=("digitalSignature",), eku=("codeSigning",), policies=[ANY])
    return pf.build_ocsp(throwaway, ca, ca_key, "good",
                         this_update=SIGNED - 100, next_update=SIGNED + 100)


# ------------------------------------------------------------- rich semantics
def _leaf_with_crl_dp(ca, issuer_key, lk, dp_uri, serial=4242):
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "L")]))
        .issuer_name(ca.subject)
        .public_key(lk.public_key())
        .serial_number(serial)
        .not_valid_before(pf.utc(1_000_000_000))
        .not_valid_after(pf.utc(2_000_000_000))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(lk.public_key()),
                       critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.3")]),
            critical=False)
        .add_extension(
            x509.CertificatePolicies(
                [x509.PolicyInformation(x509.ObjectIdentifier(ANY), [])]),
            critical=False)
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(dp_uri)],
                    relative_name=None, reasons=None, crl_issuer=None)]),
            critical=False)
        .sign(issuer_key, hashes.SHA256()))


def test_idp_distribution_point_scope_still_enforced(tmp_path):
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = _leaf_with_crl_dp(ca, ck, lk, "http://ca.test/published.crl")
    store = Store(str(tmp_path / "data"))
    sid = "es_lazy_dp_000000000000000000000000001"
    b = SetBuilder(store, sid)
    for c in (root, ca, leaf):
        b.cert(c)
    # CA CRL whose IDP names a distribution point the leaf does NOT name.
    wrong = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                         next_update=SIGNED + 100, crl_number=1,
                         idp_uris=("http://elsewhere.test/other.crl",))
    b.rev(wrong, "wrong-dp")
    b.rev(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1), "rootcrl")
    b.seal()
    res = adjudicate(store, sid, _request(leaf, fp_of(pf.der(root)), lk))
    # CRL in name/AKI scope but distribution point mismatch => no usable
    # clearance => the revocation gate rejects with UNKNOWN.
    assert res["verdict"]["status"] == "REJECTED"
    snap = {x["certificate"]: x for x in res["revocation_snapshot"]}
    leaf_res = snap[fp_of(pf.der(leaf))]
    assert leaf_res["conclusion"] == "UNKNOWN"
    reason = leaf_res["considered_evidence"][0]["reason"]
    assert "distribution point" in reason

    # Same set logic but with the matching IDP URI => GOOD.
    store2 = Store(str(tmp_path / "data2"))
    b2 = SetBuilder(store2, sid)
    for c in (root, ca, leaf):
        b2.cert(c)
    right = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                         next_update=SIGNED + 100, crl_number=1,
                         idp_uris=("http://ca.test/published.crl",))
    b2.rev(right, "right-dp")
    b2.rev(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1), "rootcrl")
    b2.seal()
    res2 = adjudicate(store2, sid, _request(leaf, fp_of(pf.der(root)), lk))
    assert res2["verdict"]["status"] == "VALID"
    store.close()
    store2.close()


def test_in_scope_malformed_crl_still_recorded(tmp_path):
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    store = Store(str(tmp_path / "data"))
    sid = "es_lazy_bad_000000000000000000000000001"
    store.create_set(sid, "c")
    rows = []
    for c in (root, ca, leaf):
        d = pf.der(c)
        store.put_blob(d)
        rows.append({"client_ref": "c" + fp_of(d)[:10], "kind": "certificate",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    # Trash bytes under a crl ref (ingestion accepts raw DER; parsing is
    # deferred until the object is in scope — this one is, via CA name...
    # note: scope pre-filter cannot match a malformed Name, so a garbage CRL
    # cannot be in issuer scope; instead corrupt a well-formed CRL body after
    # the issuer Name so the scope matches but parsing fails).
    good = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    raw = bytearray(pf.der(good))
    raw[-20] ^= 0x01  # flip signature bits; still a structurally parseable CRL
    corrupt = bytes(raw)
    store.put_blob(corrupt)
    rows.append({"client_ref": "bad", "kind": "crl",
                 "content_sha256": fp_of(corrupt), "received_at": RECEIVED})
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    d = pf.der(rcrl)
    store.put_blob(d)
    rows.append({"client_ref": "rcrl", "kind": "crl",
                 "content_sha256": fp_of(d), "received_at": RECEIVED})
    store.add_items(sid, rows)
    store.seal(sid)
    res = adjudicate(store, sid, _request(leaf, fp_of(pf.der(root)), lk))
    # Bad signature => MALFORMED_EVIDENCE disposition, verdict rejected.
    assert res["verdict"]["status"] == "REJECTED"
    snap = {x["certificate"]: x for x in res["revocation_snapshot"]}
    assert snap[fp_of(pf.der(leaf))]["conclusion"] == "MALFORMED_EVIDENCE"
    store.close()


# ------------------------------------------------------------- safety nets
def test_stale_sidecar_falls_back_to_eager(tmp_path):
    """If the revocation sidecar no longer covers the sealed universe, the
    loader falls back to exact eager blob parsing (correct verdict, never a
    silently dropped disposition)."""
    data = str(tmp_path / "data")
    sid, keys, target, noise_fps, _ = _build_noise_set(data)
    rk, ck, lk, root, ca, leaf = keys
    # Corrupt the sidecar: drop one CRL row so coverage is incomplete.
    import glob
    import json as _json

    path = glob.glob(os.path.join(data, "packages", "*.revindex.json"))[0]
    idx = _json.load(open(path))
    idx["crls"].pop()
    open(path, "w").write(_json.dumps(idx))

    store = Store(data)
    read = set()
    orig = Store.get_blob

    def traced(self, digest):
        read.add(digest)
        return orig(self, digest)

    Store.get_blob = traced
    try:
        res = adjudicate(store, sid,
                         _request(leaf, fp_of(pf.der(root)), lk))
    finally:
        Store.get_blob = orig
    # Correct verdict even though every blob had to be parsed this time.
    assert res["verdict"]["status"] == "VALID"
    assert read >= target
    store.close()


def test_out_of_profile_noise_rejection_carried_without_blob_read(tmp_path):
    """An unrelated (Noise CA) CRL that is out of profile (indirect ->
    UNSUPPORTED) was rejected at seal time. After a cold restart its verdict
    is carried in evidence dispositions without ever reading its blob."""
    store = Store(str(tmp_path / "data"))
    sid = "es_lazy_indirect_000000000000000000000001"
    b = SetBuilder(store, sid)
    rk, ck, lk, root, ca, leaf = _chain()
    for c in (root, ca, leaf):
        b.cert(c)
    b.rev(pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1), "crl")
    b.rev(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1), "rcrl")
    nk = pf.gen_key()
    noise = pf.build_cert("Noise CA", None, nk, nk, is_ca=True,
                          key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                          self_signed=True)
    b.cert(noise, "noise-ca")
    indirect = pf.build_crl(noise, nk, [], last_update=SIGNED - 100,
                            next_update=SIGNED + 100, crl_number=1,
                            indirect=True)
    indirect_fp = b.rev(indirect, "indirect")
    b.seal()

    store2 = Store(str(tmp_path / "data"))
    read = set()
    orig = Store.get_blob

    def traced(self, digest):
        read.add(digest)
        return orig(self, digest)

    Store.get_blob = traced
    try:
        res = adjudicate(store2, sid,
                         _request(leaf, fp_of(pf.der(root)), lk))
    finally:
        Store.get_blob = orig
    assert res["verdict"]["status"] == "VALID"
    # The unrelated out-of-profile CRL is still reported parse-rejected...
    rejected = {p["sha256"]: p
                for p in res["evidence_disposition"]["parse_rejected"]}
    assert indirect_fp in rejected
    assert rejected[indirect_fp]["code"] == "UNSUPPORTED"
    # ...but its DER was never read in this cold process.
    assert indirect_fp not in read
    store.close()
    store2.close()


# ------------------------------------------------------------- resource cap
def test_crl_ocsp_resource_cap_at_seal(tmp_path):
    store = Store(str(tmp_path / "data"))
    sid = "es_lazy_cap_000000000000000000000000001"
    store.create_set(sid, "c")
    nk = pf.gen_key()
    noise = pf.build_cert("Noise CA", None, nk, nk, is_ca=True,
                          key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                          self_signed=True)
    d = pf.der(noise)
    store.put_blob(d)
    rows = [{"client_ref": "ca", "kind": "certificate",
             "content_sha256": fp_of(d), "received_at": RECEIVED}]
    for i in range(2001):
        o = pf.build_crl(noise, nk, [], last_update=SIGNED + i,
                         next_update=SIGNED + 100_000 + i, crl_number=i + 1)
        raw = pf.der(o)
        store.put_blob(raw)
        rows.append({"client_ref": f"n{i}", "kind": "crl",
                     "content_sha256": fp_of(raw), "received_at": RECEIVED})
    store.add_items(sid, rows)
    with pytest.raises(ConflictError) as exc:
        store.seal(sid)
    assert exc.value.existing["limit"] == "crl_ocsp_evidence"
    assert exc.value.existing["max"] == 2000
    assert exc.value.existing["actual"] == 2001
    store.close()
