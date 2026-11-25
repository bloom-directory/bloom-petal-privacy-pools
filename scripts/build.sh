#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PETAL_REV="864a80b407387871bae06aabe77b91865e55f7bc"

if [[ -n "${PETAL_BIN:-}" ]]; then
  # Explicit override: the caller is responsible for pointing this at a
  # binary built from PETAL_REV (or a compatible superset of it).
  "$PETAL_BIN" build --root "$ROOT"
else
  # Never trust an ambient `petal` on PATH. A differently-pinned install
  # (e.g. left behind by a CI step that resolved a stale PETAL_REV, or a
  # dev's unrelated petal checkout) would silently validate this package
  # against the wrong SDK/host-capability contract and mask a real
  # incompatibility as a pass. Always install the pinned revision fresh.
  tool_root="$ROOT/target/petal-tool"
  cargo install \
    --git https://github.com/bloom-directory/petal \
    --rev "$PETAL_REV" \
    --locked \
    --root "$tool_root" \
    bloom-petal-cli
  "$tool_root/bin/petal" build --root "$ROOT"
fi
