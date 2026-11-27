#!/usr/bin/env bash
# Lean proofs → Lean-generated vectors (fail on drift) → Rust (core + program)
# → TS client, all against the same formal/vectors files.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/formal/lean"
lake build
lake exe vectors > "$root/formal/vectors/nullifier_v1.txt.new"
diff -u "$root/formal/vectors/nullifier_v1.txt" "$root/formal/vectors/nullifier_v1.txt.new"
rm "$root/formal/vectors/nullifier_v1.txt.new"
if grep -rnE '\b(sorry|admit)\b|^axiom ' "$root/formal/lean/ClawdZk"; then echo "unproved goal in Lean"; exit 1; fi
cd "$root"
cargo test --workspace --quiet
(cd client && npx vitest run)
echo "formal check OK: Lean proofs build, vectors match across Lean, Rust and TS"
