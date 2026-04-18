#!/usr/bin/env bash
# build.sh — produce a local Mac/Linux bundle of vortex-wizard.
#
# Usage:
#   ./build.sh            # default: auto-detect platform, output to dist/
#   ./build.sh --clean    # wipe build/ and dist/ first
#
# For Windows use `build.ps1`. For cross-platform CI use
# `.github/workflows/release.yml`.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

CLEAN=0
for arg in "$@"; do
    case "$arg" in
        --clean) CLEAN=1 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

# 1. Virtualenv
if [ ! -d ".venv-build" ]; then
    echo "→ creating build venv"
    python3 -m venv .venv-build
fi
# shellcheck source=/dev/null
source .venv-build/bin/activate

echo "→ installing build deps"
pip install --quiet --upgrade pip
pip install --quiet pyinstaller
pip install --quiet -r vortex_wizard/requirements.txt

# 2. Clean
if [ $CLEAN -eq 1 ]; then
    rm -rf build dist
fi

# 3. Build
echo "→ running pyinstaller"
pyinstaller vortex_wizard/vortex-wizard.spec --noconfirm

# 4. Archive
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
VER=$(python3 -c "from vortex_wizard import VERSION; print(VERSION)")
OUT_BASE="vortex-wizard-${VER}-${OS}-${ARCH}"

mkdir -p dist/archives
pushd dist >/dev/null
if [ -d "Vortex Wizard.app" ]; then
    echo "→ zipping macOS .app"
    ditto -c -k --sequesterRsrc --keepParent "Vortex Wizard.app" "archives/${OUT_BASE}.zip"
    echo "✅ archives/${OUT_BASE}.zip"
elif [ -d "vortex-wizard" ]; then
    echo "→ tarring Linux folder"
    tar -czf "archives/${OUT_BASE}.tar.gz" vortex-wizard
    echo "✅ archives/${OUT_BASE}.tar.gz"
fi
popd >/dev/null

echo
echo "Done. Binary: dist/"
ls -lah dist/ 2>/dev/null | head -10
