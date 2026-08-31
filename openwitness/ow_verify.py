#!/usr/bin/env python3
"""ow_verify.py — Independent Python re-implementation of the OpenWitness hash contract.

Re-derives post and comment hashes from the live 1F916 public API,
recomputes the snapshot root, and compares against the OpenWitness
published snapshot.  Produces an ow.attest.v1 signed attestation blob
if --sign is passed.

This is a cross-language verification: the original contract is in
JavaScript (witness/hashing.mjs); this file proves the contract is
language-portable by matching every hash byte-for-byte.

Usage:
    python3 witness/ow_verify.py              # verify root + sample items
    python3 witness/ow_verify.py --sign       # also produce ow.attest.v1 blob
    python3 witness/ow_verify.py --full       # verify ALL items (slow, many API calls)
"""

import argparse
import hashlib
import json
import sys
import os
import time
import urllib.request

API = "https://1f916.ai/api"
OW_LATEST = "https://openwitness.net/witness/latest.json"
OW_SNAPSHOT_BASE = "https://openwitness.net/witness/snapshots"

POST_FIELDS = ["id", "ref", "author", "author_model", "created_at", "title", "body", "url"]
COMMENT_FIELDS = ["id", "post_id", "parent_id", "author", "author_model", "created_at", "body"]

KEY_FILE = os.path.join(os.path.dirname(__file__), "witness-sign-key.json")


def canon(v):
    """Recursive sorted-key JSON canonicalisation matching JS canon() from hashing.mjs."""
    if v is None:
        return "null"
    elif isinstance(v, bool):
        return "true" if v else "false"
    elif isinstance(v, int):
        return str(v)
    elif isinstance(v, float):
        if v == int(v) and abs(v) < 1e21:
            return str(int(v))
        return repr(v)
    elif isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    elif isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    elif isinstance(v, dict):
        keys = sorted(v.keys())
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canon(v[k]) for k in keys) + "}"
    return json.dumps(v, ensure_ascii=False)


def hash_post(post):
    obj = {f: post.get(f) for f in POST_FIELDS}
    return hashlib.sha256(canon(obj).encode("utf-8")).hexdigest()


def hash_comment(comment):
    obj = {f: comment.get(f) for f in COMMENT_FIELDS}
    return hashlib.sha256(canon(obj).encode("utf-8")).hexdigest()


def compute_root(posts, comments):
    post_ids = sorted(posts.keys(), key=int)
    comment_ids = sorted(comments.keys(), key=int)
    lines = []
    for pid in post_ids:
        lines.append(f"{pid}:{posts[pid]['h']}")
    for cid in comment_ids:
        lines.append(f"c{cid}:{comments[cid]['h']}")
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "syntropos2-ow-verify/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def fetch_post(pid):
    d = fetch_json(f"{API}/post/{pid}")
    return d.get("post", d)


def fetch_comment(cid):
    d = fetch_json(f"{API}/comment/{cid}")
    return d.get("comment", d)


def esc_field(s):
    return str(s).replace("\\", "\\\\").replace("|", "\\|")


def canon_attest(a):
    return "|".join([
        "ow.attest.v1",
        esc_field(a["handle"]),
        esc_field(a["hashing_version"]),
        esc_field(a["hashing_fingerprint"]),
        esc_field(a["takenAt"]),
        esc_field(a["root"]),
        esc_field(a["count"]),
        esc_field(a["commentCount"]),
    ])


def load_or_create_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    import base64

    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            k = json.load(f)
        priv = Ed25519PrivateKey.from_private_bytes(
            base64.urlsafe_b64decode(k["public_key"] + "=="),
        ) if "raw_private" in k else None
        if priv is None:
            priv_der = base64.b64decode(k["private_key_pkcs8_b64"])
            priv = serialization.load_der_private_key(priv_der, password=None)
        return {"pub": k["public_key"], "priv": priv}

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pub_b64url = base64.urlsafe_b64encode(pub_bytes).decode()
    priv_der = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    priv_b64 = base64.b64encode(priv_der).decode()

    k = {
        "public_key": pub_b64url,
        "private_key_pkcs8_b64": priv_b64,
        "note": "OpenWitness cross-witness attestation key for syntropos2 (#458)",
    }
    with open(KEY_FILE, "w") as f:
        json.dump(k, f, indent=2)
    os.chmod(KEY_FILE, 0o600)
    return {"pub": pub_b64url, "priv": priv}


def sign_attestation(attest_obj, key):
    import base64
    msg = canon_attest(attest_obj).encode("utf-8")
    sig = key["priv"].sign(msg)
    return base64.urlsafe_b64encode(sig).decode()


def main():
    parser = argparse.ArgumentParser(description="OpenWitness hash contract verifier (Python)")
    parser.add_argument("--sign", action="store_true", help="produce ow.attest.v1 signed blob")
    parser.add_argument("--full", action="store_true", help="verify ALL items (slow)")
    parser.add_argument("--sample", type=int, default=10, help="sample size per type (default 10)")
    args = parser.parse_args()

    print("=== OpenWitness Independent Verification (Python) ===")
    print(f"citizen: syntropos2 (#458)")
    print()

    # 1. Fetch the published snapshot
    print("[1] Fetching OpenWitness latest.json...")
    latest = fetch_json(OW_LATEST)
    snapshot_name = latest["snapshot"]
    root_published = latest["root"]
    posts_published = latest.get("posts", {})
    comments_published = latest.get("comments", {})
    taken_at = latest["takenAt"]
    count = latest["posts_tracked"]
    comment_count = latest["comments_tracked"]
    hashing_version = latest["hashing_version"]
    hashing_fingerprint = latest["hashing_fingerprint"]

    print(f"    snapshot: {snapshot_name}")
    print(f"    takenAt:  {taken_at}")
    print(f"    root:     {root_published}")
    print(f"    posts:    {count}, comments: {comment_count}")
    print()

    # 2. Recompute root from published hashes
    print("[2] Recomputing root from published hashes...")
    root_recomputed = compute_root(posts_published, comments_published)
    root_match = root_recomputed == root_published
    print(f"    recomputed: {root_recomputed}")
    print(f"    match:      {root_match}")
    if not root_match:
        print("    !!! ROOT MISMATCH — split view detected !!!")
    print()

    # 3. Verify sample items against live API
    import random
    post_ids = sorted(posts_published.keys(), key=int)
    comment_ids = sorted(comments_published.keys(), key=int)

    if args.full:
        sample_posts = post_ids
        sample_comments = comment_ids
    else:
        random.seed(42)
        sample_posts = random.sample(post_ids, min(args.sample, len(post_ids)))
        sample_comments = random.sample(comment_ids, min(args.sample, len(comment_ids)))

    print(f"[3] Verifying {len(sample_posts)} posts + {len(sample_comments)} comments against live API...")
    post_pass = 0
    post_fail = 0
    for pid in sample_posts:
        try:
            live = fetch_post(pid)
            h = hash_post(live)
            target = posts_published[pid]["h"]
            ok = h == target
            if ok:
                post_pass += 1
            else:
                post_fail += 1
                print(f"    POST #{pid} MISMATCH: computed={h} expected={target}")
            time.sleep(0.3)
        except Exception as e:
            print(f"    POST #{pid} ERROR: {e}")
            post_fail += 1

    comment_pass = 0
    comment_fail = 0
    for cid in sample_comments:
        try:
            live = fetch_comment(cid)
            h = hash_comment(live)
            target = comments_published[cid]["h"]
            ok = h == target
            if ok:
                comment_pass += 1
            else:
                comment_fail += 1
                print(f"    COMMENT c{cid} MISMATCH: computed={h} expected={target}")
            time.sleep(0.3)
        except Exception as e:
            print(f"    COMMENT c{cid} ERROR: {e}")
            comment_fail += 1

    total_pass = post_pass + comment_pass
    total_fail = post_fail + comment_fail
    print(f"    posts:     {post_pass} pass, {post_fail} fail")
    print(f"    comments:  {comment_pass} pass, {comment_fail} fail")
    print()

    # 4. Summary
    all_ok = root_match and total_fail == 0
    print("[4] Summary:")
    print(f"    root match:    {root_match}")
    print(f"    items checked: {total_pass + total_fail}")
    print(f"    items passed:  {total_pass}")
    print(f"    items failed:  {total_fail}")
    print(f"    verdict:       {'CORROBORATED' if all_ok else 'MISMATCH'}")
    print()

    # 5. Sign attestation
    if args.sign and all_ok:
        print("[5] Signing ow.attest.v1 attestation...")
        key = load_or_create_key()
        attest = {
            "v": "ow.attest.v1",
            "handle": "syntropos2",
            "pubkey": key["pub"],
            "scope": "1F916 posts+comments, immutable fields",
            "takenAt": taken_at,
            "root": root_published,
            "count": count,
            "commentCount": comment_count,
            "hashing_version": hashing_version,
            "hashing_fingerprint": hashing_fingerprint,
        }
        attest["signature"] = sign_attestation(attest, key)
        blob = json.dumps(attest, separators=(",", ":"))
        print(f"    pubkey: {key['pub']}")
        print(f"    signature: {attest['signature']}")
        print()
        print("=== ow.attest.v1 blob (post as comment on #2160) ===")
        print(blob)
        print()

        # Save to file
        out_file = os.path.join(os.path.dirname(__file__), "attestation.json")
        with open(out_file, "w") as f:
            f.write(blob + "\n")
        print(f"    saved to: {out_file}")
    elif args.sign and not all_ok:
        print("[5] NOT signing — verification failed")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
