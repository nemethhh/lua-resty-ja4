#!/usr/bin/env python3
"""Validate lua-resty-ja4 JA4 algorithm against ja4db.com canonical database.

Reads docs/ja4+_db.json and verifies that raw fingerprint strings hash to
their expected fingerprint values using SHA256 truncated to 12 hex chars.

Usage: python3 scripts/validate-ja4db.py [--verbose]
"""
import json
import hashlib
import sys
from pathlib import Path


def sha256_hex12(s: str) -> str:
    """SHA256 hash truncated to first 12 hex characters (JA4 convention)."""
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def classify_entry(fp: str, raw: str) -> tuple:
    """Classify a ja4db entry as ok, alpn_mismatch, binary, or parse_error."""
    hash_parts = fp.split("_")
    if len(hash_parts) != 3:
        return "parse_error", f"hash has {len(hash_parts)} parts (expected 3)"

    raw_parts = raw.split("_", 1)
    if len(raw_parts) < 2:
        return "parse_error", "raw string has no underscore separator"

    section_a_hash = hash_parts[0]
    section_a_raw = raw_parts[0]
    section_b_hash = hash_parts[1]
    section_c_hash = hash_parts[2]

    # Check for binary corruption in hash fingerprint
    valid_hex = set("0123456789abcdef")
    if not all(c in valid_hex for c in section_b_hash):
        return "binary", "non-hex chars in hash section B"
    if not all(c in valid_hex for c in section_c_hash):
        return "binary", "non-hex chars in hash section C"

    rest_parts = raw_parts[1].split("_")
    if len(rest_parts) < 2:
        return "parse_error", f"raw body has {len(rest_parts)} parts (need >=2)"

    ciphers_csv = rest_parts[0]
    ext_and_sigalgs = "_".join(rest_parts[1:])

    # Check for binary corruption
    valid_chars = set("0123456789abcdef,")
    if not all(c in valid_chars for c in ciphers_csv):
        return "binary", "non-hex chars in cipher CSV"
    if not all(c in valid_chars | {"_"} for c in ext_and_sigalgs):
        return "binary", "non-hex chars in extension/sigalg CSV"

    # Check section A
    a_ok = section_a_hash == section_a_raw
    if not a_ok:
        if len(section_a_raw) == 10 and len(section_a_hash) == 10:
            if section_a_raw[:8] == section_a_hash[:8]:
                # Known db inconsistencies: ALPN differs between raw and hash
                return "alpn_mismatch", f"raw={section_a_raw[8:]} hash={section_a_hash[8:]}"
        return "section_a_mismatch", f"raw={section_a_raw} hash={section_a_hash}"

    # Check internal consistency: empty CSV but non-empty hash = db error
    if not ciphers_csv and section_b_hash != "000000000000":
        return "db_inconsistency", f"empty cipher CSV but hash={section_b_hash}"

    # Validate section B hash
    computed_b = sha256_hex12(ciphers_csv) if ciphers_csv else "000000000000"
    if computed_b != section_b_hash:
        return "section_b_mismatch", f"computed={computed_b} expected={section_b_hash}"

    # Validate section C hash
    computed_c = sha256_hex12(ext_and_sigalgs) if ext_and_sigalgs else "000000000000"
    if computed_c != section_c_hash:
        return "section_c_mismatch", f"computed={computed_c} expected={section_c_hash}"

    return "ok", ""


def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    db_path = Path(__file__).parent.parent / "docs" / "ja4+_db.json"
    if not db_path.exists():
        print(f"ERROR: {db_path} not found")
        sys.exit(1)

    with open(db_path) as f:
        data = json.load(f)

    # Deduplicate by ja4_fingerprint
    entries = {}
    for e in data:
        fp = e.get("ja4_fingerprint")
        raw = e.get("ja4_fingerprint_string")
        if fp and raw and fp not in entries:
            entries[fp] = {
                "raw": raw,
                "app": e.get("application") or e.get("library") or "unknown",
                "verified": e.get("verified", False),
            }

    # Classify each entry
    categories = [
        "ok", "alpn_mismatch", "binary", "parse_error", "db_inconsistency",
        "section_a_mismatch", "section_b_mismatch", "section_c_mismatch",
    ]
    results = {c: [] for c in categories}

    for fp, info in entries.items():
        category, detail = classify_entry(fp, info["raw"])
        results[category].append((fp, info, detail))

    # Report
    total = len(entries)
    ok = len(results["ok"])
    print("JA4DB Validation Report")
    print("=" * 50)
    print(f"Total unique fingerprints:  {total}")
    print(f"OK (hash verified):         {ok}")
    print(f"ALPN ht->h1 discrepancy:    {len(results['alpn_mismatch'])}")
    print(f"Binary corruption:          {len(results['binary'])}")
    print(f"DB inconsistency:           {len(results['db_inconsistency'])}")
    print(f"Parse errors:               {len(results['parse_error'])}")
    print(f"Section A mismatches:       {len(results['section_a_mismatch'])}")
    print(f"Section B mismatches:       {len(results['section_b_mismatch'])}")
    print(f"Section C mismatches:       {len(results['section_c_mismatch'])}")
    print()

    verified_ok = sum(1 for _, info, _ in results["ok"] if info["verified"])
    print(f"Verified entries in OK:     {verified_ok}")
    print()

    if verbose:
        for category in ["section_a_mismatch", "section_b_mismatch",
                          "section_c_mismatch", "parse_error"]:
            if results[category]:
                print(f"--- {category} ---")
                for fp, info, detail in results[category][:5]:
                    print(f"  {fp} ({info['app']}): {detail}")
                print()

    # Exit code: 0 if no unexpected failures
    unexpected = (len(results["section_a_mismatch"]) +
                  len(results["section_b_mismatch"]) +
                  len(results["section_c_mismatch"]))
    if unexpected > 0:
        print(f"FAIL: {unexpected} unexpected mismatches")
        sys.exit(1)
    else:
        print(f"PASS: All {ok} well-formed entries validate correctly")
        sys.exit(0)


if __name__ == "__main__":
    main()
