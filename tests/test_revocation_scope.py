"""Lazy revocation materialization.

Unrelated revocation evidence (a Noise CA with no scope relationship to the
adjudicated chain) must never be fully parsed — not on the first fresh-process
adjudication after a restart and not on a cache-miss request.  These tests
instrument both the full DER parser and blob reads, and assert the target
chain's verdict/evidence disposition is unchanged.
"""
import hashlib
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app import evidence as ev
from app.adjudge import adjudicate, normalize_request, run_core
from app.certmodel import fp_of
from app.loader import LoadedSet
from app.package import build_package
from app.storage import Store
from verify.verify_package import verify_package

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000


def _target_pki():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("Target Root", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"),
                         policies=[ANY], self_signed=True)
    ca = pf.build_cert("Target CA", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("target.leaf", ca, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("target.leaf",))
    return rk, ck, lk, root, ca, leaf


def _noise_crl(i):
    nk = pf.gen_key()
    nca = pf.build_cert(f"Noise CA {i}", None, nk, nk, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"),
                        policies=[ANY], self_signed=True)
    return pf.build_crl(nca, nk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)


def _build_sealed(store, sid, certs, revos, noise_n=0):
    store.create_set(sid, "c")
    rows = []
    for c in certs:
        d = pf.der(c)
        store.put_blob(d)
        rows.append({"client_ref": "c" + fp_of(d)[:10], "kind": "certificate",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    for i, (kind, o) in enumerate(revos):
        d = pf.der(o)
        store.put_blob(d)
        rows.append({"client_ref": f"r{i}", "kind": kind,
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    noise = set()
    for i in range(noise_n):
        d = pf.der(_noise_crl(i))
        store.put_blob(d)
        noise.add(fp_of(d))
        rows.append({"client_ref": f"noise{i}", "kind": "crl",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    store.add_items(sid, rows)
    return store.seal(sid), noise


def _request(leaf, root, lk):
    d = hashlib.sha256(b"artifact").digest()
    s = lk.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
    return {
        "artifact_digest": d.hex(), "signature": s.hex(),
        "signature_algorithm": "1.2.840.10045.4.3.2",
        "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
        "leaf_certificate_sha256": fp_of(pf.der(leaf)),
        "initial_policies": [ANY], "trust_anchors": [fp_of(pf.der(root))]}


def test_unrelated_crls_never_fully_parsed(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "data"))
    rk, ck, lk, root, ca, leaf = _target_pki()
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=2)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    _m, noise = _build_sealed(store, "es_scope1", (root, ca, leaf),
                              (("crl", crl), ("crl", rcrl)), noise_n=48)

    parsed = []
    orig = ev.parse_crl
    monkeypatch.setattr(ev, "parse_crl",
                        lambda raw, rec: (parsed.append(fp_of(raw))
                                          or orig(raw, rec)))
    res = adjudicate(store, "es_scope1", _request(leaf, root, lk))
    assert res["verdict"]["status"] == "VALID"
    assert len(parsed) == 2
    assert not (set(parsed) & noise)


def test_fresh_process_after_restart_uses_scope_sidecar(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "data"))
    rk, ck, lk, root, ca, leaf = _target_pki()
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=2)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    manifest, noise = _build_sealed(store, "es_scope2", (root, ca, leaf),
                                    (("crl", crl), ("crl", rcrl)), noise_n=48)
    assert os.path.exists(os.path.join(
        store.root, "packages", "es_scope2.revindex.json"))
    store.close()

    # Reopen like a brand new process/instance sharing the persistent volume.
    store2 = Store(str(tmp_path / "data"))
    read_blobs = set()
    orig_get = store2.get_blob
    monkeypatch.setattr(store2, "get_blob",
                        lambda dg: (read_blobs.add(dg), orig_get(dg))[1])
    parsed = []
    orig_parse = ev.parse_crl
    monkeypatch.setattr(ev, "parse_crl",
                        lambda raw, rec: (parsed.append(fp_of(raw))
                                          or orig_parse(raw, rec)))
    req = normalize_request(_request(leaf, root, lk))
    loaded = LoadedSet.from_store(store2, manifest)
    res = run_core(loaded, manifest, req)
    assert res["verdict"]["status"] == "VALID"
    assert len(parsed) == 2
    assert not (set(parsed) & noise)
    # Unrelated revocation DER is not even read from disk.
    assert not (read_blobs & noise)

    # A second, previously uncached adjudication in the same process also
    # stays lazy (different request digest -> no stored-result replay).
    parsed.clear()
    req2 = dict(_request(leaf, root, lk))
    req2["knowledge_cutoff"] = CUTOFF + 1
    loaded2 = LoadedSet.from_store(store2, manifest)
    res2 = run_core(loaded2, manifest, normalize_request(req2))
    assert res2["verdict"]["status"] == "VALID"
    assert not (set(parsed) & noise)


def test_package_omits_unrelated_crl_and_offline_verifies(tmp_path):
    import zipfile

    store = Store(str(tmp_path / "data"))
    rk, ck, lk, root, ca, leaf = _target_pki()
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=2)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    manifest, noise = _build_sealed(store, "es_scope3", (root, ca, leaf),
                                    (("crl", crl), ("crl", rcrl)), noise_n=48)
    res = adjudicate(store, "es_scope3", _request(leaf, root, lk))
    pkg = build_package(store, res, manifest)
    path = tmp_path / "p.zip"
    path.write_bytes(pkg)
    names = zipfile.ZipFile(path).namelist()
    bundled_crls = {n.split("/")[-1].removesuffix(".der")
                    for n in names if n.startswith("der/crls/")}
    assert not (bundled_crls & noise)
    assert len(bundled_crls) == 2
    report = verify_package(str(path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]


def test_full_and_delta_selection_with_noise(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "data"))
    rk, ck, lk, root, ca, leaf = _target_pki()
    base = pf.build_crl(ca, ck, [(leaf.serial_number, SIGNED - 200_000,
                                  "certificate_hold")],
                        last_update=SIGNED - 300_000,
                        next_update=SIGNED + 300_000, crl_number=10)
    delta = pf.build_crl(ca, ck, [(leaf.serial_number, SIGNED - 200_000,
                                   "remove_from_crl")],
                         last_update=SIGNED - 1_000,
                         next_update=SIGNED + 300_000, crl_number=11,
                         delta_of=10)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 300_000,
                        next_update=SIGNED + 300_000, crl_number=1)
    _m, noise = _build_sealed(store, "es_scope4", (root, ca, leaf),
                              (("crl", base), ("crl", delta), ("crl", rcrl)),
                              noise_n=48)
    parsed = []
    orig = ev.parse_crl
    monkeypatch.setattr(ev, "parse_crl",
                        lambda raw, rec: (parsed.append(fp_of(raw))
                                          or orig(raw, rec)))
    res = adjudicate(store, "es_scope4", _request(leaf, root, lk))
    assert res["verdict"]["status"] == "VALID"
    sel = res["revocation_results"][0]["selected_evidence"]
    assert sel["kind"] == "crl"
    assert sel["delta"] == fp_of(pf.der(delta))
    assert not (set(parsed) & noise)


def test_unrelated_ocsps_never_fully_parsed(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import hashes as H

    store = Store(str(tmp_path / "data"))
    rk, ck, lk, root, ca, leaf = _target_pki()
    oc = pf.build_ocsp(leaf, ca, ck, "good", this_update=SIGNED - 100,
                       next_update=SIGNED + 100, hash_alg=H.SHA256())
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    store.create_set("es_scope5", "c")
    rows = []
    for c in (root, ca, leaf):
        d = pf.der(c)
        store.put_blob(d)
        rows.append({"client_ref": "c" + fp_of(d)[:10], "kind": "certificate",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    for ref, o in (("oc", oc), ("rc", rcrl)):
        kind = "ocsp" if ref == "oc" else "crl"
        d = pf.der(o)
        store.put_blob(d)
        rows.append({"client_ref": ref, "kind": kind,
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    noise = set()
    for i in range(20):
        nk = pf.gen_key()
        nca = pf.build_cert(f"OCSP Noise CA {i}", None, nk, nk, is_ca=True,
                            key_usage=("keyCertSign", "cRLSign"),
                            policies=[ANY], self_signed=True)
        nleaf = pf.build_cert(f"nleaf{i}", nca, pf.gen_key(), nk,
                              key_usage=("digitalSignature",),
                              eku=("codeSigning",), policies=[ANY])
        noc = pf.build_ocsp(nleaf, nca, nk, "good", this_update=SIGNED - 100,
                            next_update=SIGNED + 100, hash_alg=H.SHA1())
        d = pf.der(noc)
        store.put_blob(d)
        noise.add(fp_of(d))
        rows.append({"client_ref": f"noise{i}", "kind": "ocsp",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    store.add_items("es_scope5", rows)
    store.seal("es_scope5")

    parsed = []
    orig = ev.parse_ocsp
    monkeypatch.setattr(ev, "parse_ocsp",
                        lambda raw, rec: (parsed.append(fp_of(raw))
                                          or orig(raw, rec)))
    res = adjudicate(store, "es_scope5", _request(leaf, root, lk))
    assert res["verdict"]["status"] == "VALID"
    assert len(parsed) == 1
    assert not (set(parsed) & noise)


def test_idp_distribution_point_scope_matching(tmp_path):
    """A CRL whose IDP distribution point is not named by the certificate's
    cRLDistributionPoints extension is scope-excluded; the matching CRL wins."""
    store = Store(str(tmp_path / "data"))
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"),
                         policies=[ANY], self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert(
        "L", ca, lk, ck, key_usage=("digitalSignature",),
        eku=("codeSigning",), policies=[ANY],
        crl_dp_uris=("http://ca.example/leaf.crl",))
    matching = pf.build_crl(
        ca, ck, [], last_update=SIGNED - 100, next_update=SIGNED + 100,
        crl_number=2, idp_uris=("http://ca.example/leaf.crl",))
    mismatched = pf.build_crl(
        ca, ck, [], last_update=SIGNED - 100, next_update=SIGNED + 100,
        crl_number=3, idp_uris=("http://ca.example/other.crl",))
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    sid = "es_scope6"
    store.create_set(sid, "c")
    rows = []
    for c in (root, ca, leaf):
        d = pf.der(c)
        store.put_blob(d)
        rows.append({"client_ref": "c" + fp_of(d)[:10], "kind": "certificate",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    for ref, o in (("match", matching), ("mismatch", mismatched),
                   ("rc", rcrl)):
        d = pf.der(o)
        store.put_blob(d)
        rows.append({"client_ref": ref, "kind": "crl",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    store.add_items(sid, rows)
    store.seal(sid)
    res = adjudicate(store, sid, _request(leaf, root, lk))
    assert res["verdict"]["status"] == "VALID"
    leaf_rev = next(r for r in res["revocation_snapshot"]
                    if r["certificate"] == fp_of(pf.der(leaf)))
    by_fp = {c["fingerprint"]: c for c in leaf_rev["considered_evidence"]}
    assert by_fp[fp_of(pf.der(mismatched))]["decision"] == "EXCLUDED"
    assert "distribution point" in by_fp[fp_of(pf.der(mismatched))]["reason"]
    assert by_fp[fp_of(pf.der(matching))]["decision"] == "USED"


def test_scope_header_entry_count_matches_library(tmp_path):
    from cryptography import x509

    store = Store(str(tmp_path / "data"))
    rk, ck, lk, root, ca, leaf = _target_pki()
    entries = [(leaf.serial_number, SIGNED - 100, "key_compromise"),
               (leaf.serial_number + 1, SIGNED - 90, "cessation_of_operation")]
    crl = pf.build_crl(ca, ck, entries, last_update=SIGNED - 1000,
                       next_update=SIGNED + 1000, crl_number=1)
    raw = pf.der(crl)
    header = ev.crl_scope_header(raw)
    assert header["entry_count"] == len(x509.load_der_x509_crl(raw))
    assert header["crl_number"] == 1
    assert header["base_crl_number"] is None
    assert header["issuer_der"] == ev.parse_crl(raw, RECEIVED).issuer_der
