"""Process-local instrumentation for lazy revocation materialization.

The adjudication core fully DER-parses a CRL/OCSP object only when its scope
matches a certificate under evaluation. This module records, per evidence
set, exactly which revocation DERs a process actually materialized, so the
acceptance chain can prove that unrelated archived evidence (e.g. 48 CRLs
issued by an unrelated Noise CA) is never parsed after a restart, instance
switch or adjudication-cache miss.

State is intentionally process-local and never persisted; each API instance
starts empty, which is exactly the cold-process scenario under test.
"""
from __future__ import annotations

import threading

_lock = threading.Lock()
# set_id -> {"crl": set[digest], "ocsp": set[digest]}
_parsed: dict[str, dict[str, set[str]]] = {}


def record_parsed(set_id: str, kind: str, digest: str) -> None:
    with _lock:
        bucket = _parsed.setdefault(set_id, {"crl": set(), "ocsp": set()})
        bucket[kind].add(digest)


def snapshot() -> dict:
    with _lock:
        return {
            set_id: {
                "crl_full_parsed": sorted(buckets["crl"]),
                "ocsp_full_parsed": sorted(buckets["ocsp"]),
            }
            for set_id, buckets in sorted(_parsed.items())
        }


def reset() -> None:
    with _lock:
        _parsed.clear()
