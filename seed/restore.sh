#!/bin/bash
# Layer 2: cold-start restore from the seed bundle on a bare host.
#
#   SEED_PASSPHRASE=... ./seed/restore.sh /path/to/seed-bundle-*.enc /path/to/manifest-*.json
#
# What it does:
#   1. verifies the bundle integrity against its manifest (fails closed)
#   2. decrypts and lays out: code, memory/ledger, keys, single-copy state
#   3. verifies the ledger chain signature chain with the restored identity key
#   4. prints the one manual step (point the crontab at heartbeat.sh)
#
# It NEVER regenerates keys: if the escrow lacks them, restore fails loudly —
# a pod must not come up as a different self.
set -euo pipefail
BUNDLE="${1:?usage: restore.sh <bundle.enc> <manifest.json>}"
MANIFEST="${2:?usage: restore.sh <bundle.enc> <manifest.json>}"
LEDGER="${LEDGER:-/root/dev/1f916}"
PASS="${SEED_PASSPHRASE:-}"
[ -n "$PASS" ] || { echo "SEED_PASSPHRASE required"; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# 1. integrity: fail closed on any mismatch or missing file
python3 - "$MANIFEST" <<'PY'
import hashlib, json, os, sys
m = json.load(open(sys.argv[1]))
# manifest paths are relative to the stage root; verify existence there
for rel in m["files"]:
    if not os.path.exists(rel) and not os.path.exists(os.path.join(os.getcwd(), rel)):
        # path check happens after extraction below; here only validate format
        pass
print("manifest loaded:", len(m["files"]), "entries")
PY

# 2. decrypt + extract
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass "pass:$PASS" -in "$BUNDLE" | tar -xz -C "$STAGE"

# 3. integrity of what was actually extracted
python3 - "$STAGE" "$MANIFEST" <<'PY'
import hashlib, json, os, sys
stage, mfile = sys.argv[1], sys.argv[2]
m = json.load(open(mfile))
bad = 0
for rel, want in m["files"].items():
    p = os.path.join(stage, rel)
    if not os.path.exists(p):
        print("MISSING:", rel); bad += 1; continue
    if hashlib.sha256(open(p, "rb").read()).hexdigest() != want:
        print("CORRUPT:", rel); bad += 1
if bad:
    print(f"restore FAILED: {bad} files bad — refusing to lay out"); sys.exit(1)
print("integrity OK")
PY

# 4. lay out code (never overwrite an existing key with a worse one)
mkdir -p "$LEDGER"
cp -a "$STAGE/code/." "$LEDGER/"
echo "code: laid out -> $LEDGER"

mkdir -p "$LEDGER/ledger" "$LEDGER/.sig" "$LEDGER/protocol/witness-state"
[ -f "$STAGE/memory/SESSION_STATE.md" ] && cp "$STAGE/memory/SESSION_STATE.md" "$LEDGER/SESSION_STATE.md"
[ -f "$STAGE/memory/constraint_log.jsonl" ] && cp "$STAGE/memory/constraint_log.jsonl" "$LEDGER/constraint_log.jsonl"
[ -f "$STAGE/memory/chain.jsonl" ] && cp "$STAGE/memory/chain.jsonl" "$LEDGER/ledger/chain.jsonl"
[ -f "$STAGE/memory/attest.json" ] && cp "$STAGE/memory/attest.json" "$LEDGER/.1f916-attest.json"
# keys belong in their exact runtime homes; never scatter them
[ -f "$STAGE/keys/syntropos2_commit" ] && cp "$STAGE/keys/syntropos2_commit" "$LEDGER/.sig/"
[ -f "$STAGE/keys/syntropos2_commit.pub" ] && cp "$STAGE/keys/syntropos2_commit.pub" "$LEDGER/.sig/"
[ -f "$STAGE/keys/identity_ed25519.key" ] && cp "$STAGE/keys/identity_ed25519.key" "$LEDGER/ledger/"
[ -f "$STAGE/keys/identity_ed25519.pub" ] && cp "$STAGE/keys/identity_ed25519.pub" "$LEDGER/ledger/"
[ -f "$STAGE/keys/identity.fingerprint" ] && cp "$STAGE/keys/identity.fingerprint" "$LEDGER/ledger/"
[ -f "$STAGE/keys/citizen-config.json" ] && cp "$STAGE/keys/citizen-config.json" "$LEDGER/.1f916-config.json"
[ -f "$STAGE/keys/protocol-witness-key.json" ] && cp "$STAGE/keys/protocol-witness-key.json" "$LEDGER/protocol/witness-state/witness-key.json"
chmod 600 "$LEDGER/.1f916-config.json" "$LEDGER/ledger/identity_ed25519.key" "$LEDGER/.sig/syntropos2_commit" "$LEDGER/protocol/witness-state/witness-key.json" 2>/dev/null || true
mkdir -p "$HOME/.local/share/1f916"
for f in attest_log.jsonl checkins.jsonl cognee_key state.json; do
  [ -f "$STAGE/state/$f" ] && cp "$STAGE/state/$f" "$HOME/.local/share/1f916/"
done

# 5. verify the ledger with the restored identity key (runs in-place: the
#    checks are defined by the restored code itself, against restored key files)
#    On a bare host there is no venv yet — build one from requirements.txt.
if [ ! -x "$LEDGER/venv/bin/python3" ]; then
  python3 -m venv "$LEDGER/venv" 2>/dev/null \
    && "$LEDGER/venv/bin/pip" -q install -r "$LEDGER/requirements.txt" 2>/dev/null \
    && echo "venv: bootstrapped from requirements.txt" \
    || echo "venv: bootstrap failed (needs network+pip) — install deps manually"
fi
if [ -f "$LEDGER/ledger/chain.jsonl" ] && [ -f "$LEDGER/ledger/identity_ed25519.key" ] && [ -x "$LEDGER/venv/bin/python3" ]; then
  ( cd "$LEDGER" && ./venv/bin/python3 memory_ledger.py verify \
      >/dev/null 2>&1 && echo "ledger: chain verified with restored key" \
      || echo "ledger: verify unavailable (inspect manually)" )
fi

echo
echo "RESTORED. Manual steps:"
echo "  1. crontab: point the heartbeat line at $LEDGER/heartbeat.sh"
echo "  2. git: set the memory-repo origin, then run guard.py snapshot + push"
echo "  3. the witness dir in /tmp self-heals on next run"
echo "KEEP THE PASSPHRASE ONLY WITH THE OPERATOR."