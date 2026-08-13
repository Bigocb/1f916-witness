#!/bin/bash
# Layer 2: assemble the complete survivable seed and encrypt the sensitive
# material into an escrow bundle.
#
#   SEED_PASSPHRASE=<passphrase> ./seed/build.sh
#
# Produces:
#   seed/escrow/seed-bundle-<ts>.enc   encrypted tar.gz (code + memory + keys)
#   seed/escrow/manifest-<ts>.json     plaintext sha256 manifest for integrity
#
# Restore on a bare host:  SEED_PASSPHRASE=... ./seed/restore.sh <bundle> <manifest>
#
# The passphrase is the ONLY thing this build cannot survive without. It is
# never written to disk by this script — set it in the environment or stdin.
set -euo pipefail
LEDGER="${LEDGER:-/root/dev/1f916}"
HERE="$LEDGER/seed"
OUT="$HERE/escrow"
STAGE=$(mktemp -d)
TAR="$HERE/bundle.tmp.tar.gz"
trap 'rm -rf "$STAGE" "$TAR"' EXIT
mkdir -p "$OUT"

PASS="${SEED_PASSPHRASE:-}"
if [ -z "$PASS" ]; then
  echo "SEED_PASSPHRASE is required (never stored to disk by this script)" >&2
  exit 1
fi
if [ ${#PASS} -lt 24 ]; then
  echo "passphrase too short — use >=24 chars" >&2
  exit 1
fi

TS=$(date -u +%Y%m%dT%H%M%SZ)
echo "building seed bundle @ $TS"

# ---- 1. code + prompts + policies: the durable self. The canonical memory
#        repo is the source of truth for the protected personality (VOICE,
#        GUARDRAILS, all prompts) — the working git repo is NOT (most of those
#        are untracked there). Snapshot from canonical first, then overlay the
#        working dir, then add the newest durable files explicitly.
mkdir -p "$STAGE/code"
if [ -f /srv/git/syntropos2-memory.git/HEAD ]; then
  git --git-dir=/srv/git/syntropos2-memory.git archive --format=tar HEAD | tar -x -C "$STAGE/code"
  echo "  archived canonical memory repo (protected self)"
fi
# overlay the working dir for the full picture (excludes generated/volatile)
rsync -a --exclude '.git' --exclude 'venv' --exclude '__pycache__' \
  --exclude '*.pyc' --exclude '*.log' --exclude 'heartbeat.log' \
  --exclude '*.log.*' --exclude '.opencode' --exclude 'wallet' \
  --exclude '.1f916-config.json' --exclude '.sig' --exclude 'ledger/identity_ed25519.key' \
  --exclude 'protocol/witness-state' --exclude 'seed/escrow' \
  "$LEDGER/" "$STAGE/code/" 2>/dev/null || true
# files that exist only in the working dir and are part of the self
for extra in centers/attention/selfwake.py centers/attention/selfwake.sh boot_check.sh $LEDGER/seed/bundle.notes protocol/witness.mjs; do
  src="${extra#\$LEDGER/}"
  if [ -f "$extra" ]; then mkdir -p "$STAGE/code/$(dirname "$src")"; cp "$extra" "$STAGE/code/$src"; fi
  src2="${extra#/root/dev/1f916/}"
  if [ -f "$src2" ]; then mkdir -p "$STAGE/code/$(dirname "$src2")"; cp "$src2" "$STAGE/code/$src2"; fi
done

# ---- 2. memory + ledger (the durable self's write-ahead log)
mkdir -p "$STAGE/memory"
cp "$LEDGER/ledger/chain.jsonl" "$STAGE/memory/chain.jsonl" 2>/dev/null || true
cp "$LEDGER/SESSION_STATE.md"    "$STAGE/memory/SESSION_STATE.md" 2>/dev/null || true
cp "$LEDGER/constraint_log.jsonl" "$STAGE/memory/constraint_log.jsonl" 2>/dev/null || true
cp "$LEDGER/.1f916-attest.json"  "$STAGE/memory/attest.json" 2>/dev/null || true

# ---- 3. keys (belong ONLY in the encrypted bundle, never plaintext in git)
mkdir -p "$STAGE/keys"
cp "$LEDGER/.sig/syntropos2_commit"          "$STAGE/keys/" 2>/dev/null || true
cp "$LEDGER/.sig/syntropos2_commit.pub"      "$STAGE/keys/" 2>/dev/null || true
cp "$LEDGER/ledger/identity_ed25519.key"     "$STAGE/keys/" 2>/dev/null || true
cp "$LEDGER/ledger/identity_ed25519.pub"     "$STAGE/keys/" 2>/dev/null || true
cp "$LEDGER/ledger/identity.fingerprint"     "$STAGE/keys/" 2>/dev/null || true
# citizen config = the secret that authorizes board actions (seal/witness)
cp "$LEDGER/.1f916-config.json" "$STAGE/keys/citizen-config.json" 2>/dev/null || true
# the recovered protocol witness identity — also encrypted, never committed
cp "$LEDGER/protocol/witness-state/witness-key.json" "$STAGE/keys/protocol-witness-key.json" 2>/dev/null || true

# ---- 4. single-copy state from outside the repo (nothing else backs these up)
mkdir -p "$STAGE/state"
cp "$HOME/.local/share/1f916/attest_log.jsonl" "$STAGE/state/" 2>/dev/null || true
cp "$HOME/.local/share/1f916/checkins.jsonl"   "$STAGE/state/" 2>/dev/null || true
cp "$HOME/.local/share/1f916/cognee_key"       "$STAGE/state/" 2>/dev/null || true
cp "$HOME/.local/share/1f916/state.json"       "$STAGE/state/" 2>/dev/null || true

# ---- 5. build manifest while everything is still plaintext
python3 - "$STAGE" "$OUT" "$TS" <<'PY'
import hashlib, json, os, sys
stage, out, ts = sys.argv[1], sys.argv[2], sys.argv[3]
manifest = {"ts": ts, "created_by": "seed/build.sh", "files": {}}
for root, _dirs, files in os.walk(stage):
    for f in files:
        p = os.path.join(root, f)
        rel = os.path.relpath(p, stage)
        manifest["files"][rel] = hashlib.sha256(open(p, "rb").read()).hexdigest()
mjson = os.path.join(out, f"manifest-{ts}.json")
json.dump(manifest, open(mjson, "w"), indent=1)
print(f"manifest: {len(manifest['files'])} files")
PY

# ---- 6. encrypt the whole stage into a single bundle
tar -czf "$TAR" -C "$STAGE" .
openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -pass "pass:$PASS" -in "$TAR" -out "$OUT/seed-bundle-$TS.enc"
chmod 600 "$OUT/seed-bundle-$TS.enc"
echo "wrote $OUT/seed-bundle-$TS.enc ($(du -h "$OUT/seed-bundle-$TS.enc" | cut -f1))"
echo "wrote $OUT/manifest-$TS.json ($(du -h "$OUT/manifest-$TS.json" | cut -f1))"
echo
echo "NEXT: commit escrow/ to canonical AND GitHub (off-machine). Keep the passphrase ONLY with the operator."