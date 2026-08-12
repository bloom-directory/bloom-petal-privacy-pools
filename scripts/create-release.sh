#!/usr/bin/env bash
# Creates a GitHub release for bloom-petal-privacy-pools with all artifacts.
# Usage: GH_TOKEN=<token> VERSION=0.1.3 bash scripts/create-release.sh
set -euo pipefail

REPO="bloom-directory/bloom-petal-privacy-pools"
VERSION="${VERSION:-0.1.3}"
TAG="v${VERSION}"
STAGING="${STAGING:-/tmp/privacy-pools-release}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -z "${GH_TOKEN:-}" ]; then
  echo "Error: GH_TOKEN environment variable is required"
  echo "Create a token at https://github.com/settings/tokens (needs repo scope)"
  exit 1
fi

# Resolve commit SHA
COMMIT=$(cd "$ROOT" && git rev-parse HEAD)
PETAL_REV=$(grep 'PETAL_REV=' "$ROOT/scripts/build.sh" | sed 's/.*"\(.*\)"/\1/')

echo "=== Creating release $TAG ==="
echo "  repo:   $REPO"
echo "  commit: $COMMIT"
echo "  tag:    $TAG"
echo ""

# Verify staging directory has artifacts
if [ ! -f "$STAGING/privacy-pools-v${VERSION}.petal.tar.gz" ]; then
  echo "Error: archive not found at $STAGING/privacy-pools-v${VERSION}.petal.tar.gz"
  echo "Build and package first:"
  echo "  bash scripts/build.sh"
  echo "  ./target/petal-tool/bin/petal package --out $STAGING/privacy-pools-v${VERSION}.petal.tar.gz"
  exit 1
fi

# Create the release
RELEASE_JSON=$(curl -s -X POST \
  -H "Authorization: token $GH_TOKEN" \
  -H "Content-Type: application/json" \
  "https://api.github.com/repos/$REPO/releases" \
  -d "$(cat <<EOF
{
  "tag_name": "$TAG",
  "target_commitish": "$COMMIT",
  "name": "$TAG",
  "body": "## privacy-pools petal $TAG\n\n0xBOW Privacy Pools integration for Ethereum mainnet.\n\n**15 routes** — deposits, notes, direct-withdrawal staging/reconciliation, pool reads, status, protocol\n\n**Local tools**: encrypted note backup/restore, pinned official-SDK prover, artifact verification\n\n**Supported asset**: ETH (native)\n\n**Capabilities**: bloom:store, bloom:tx.outbox, bloom:chain, bloom:vfs.read, bloom:private-input",
  "draft": false,
  "prerelease": false
}
EOF
)")

RELEASE_ID=$(echo "$RELEASE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
UPLOAD_URL="https://uploads.github.com/repos/$REPO/releases/$RELEASE_ID/assets"

echo "Release ID: $RELEASE_ID"
echo "Uploading assets..."

for file in petal-release.json SHA256SUMS "privacy-pools-v${VERSION}.petal.tar.gz"; do
  echo "  Uploading $file..."
  if [[ "$file" == *.tar.gz ]]; then
    CONTENT_TYPE="application/gzip"
  else
    CONTENT_TYPE="text/plain"
  fi
  curl -s -X POST \
    -H "Authorization: token $GH_TOKEN" \
    -H "Content-Type: $CONTENT_TYPE" \
    --data-binary "@$STAGING/$file" \
    "$UPLOAD_URL?name=$file" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'    ✓ {d[\"name\"]} ({d[\"size\"]} bytes)')"
done

echo ""
echo "Release $TAG published: https://github.com/$REPO/releases/tag/$TAG"
