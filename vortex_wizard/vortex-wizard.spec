# PyInstaller spec for `vortex-wizard`.
#
# Usage:
#   cd <project root>
#   pyinstaller vortex_wizard/vortex-wizard.spec --clean --noconfirm
#
# Produces:
#   dist/vortex-wizard              (macOS .app via --windowed)
#   dist/vortex-wizard/             (Windows/Linux folder build)
#
# The bundle is signed elsewhere (codesign / signtool) — this spec only
# builds the raw executable.
from __future__ import annotations

import sys
from pathlib import Path

block_cipher = None
ROOT = Path(SPECPATH).resolve().parent  # project root

datas = [
    # Ship the entire web/ tree so the FastAPI server can serve it
    (str(ROOT / 'vortex_wizard' / 'web'), 'vortex_wizard/web'),
]

hiddenimports = [
    'uvicorn.logging',
    'uvicorn.loops.auto',
    'uvicorn.loops.uvloop',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.lifespan.on',
    'cryptography',
    'cryptography.hazmat.primitives.asymmetric.ed25519',
    'httpx',
    # pywebview dispatchers chosen at runtime; PyInstaller can't detect them
    'webview',
    'webview.platforms.cocoa',
    'webview.platforms.winforms',
    'webview.platforms.gtk',
    'webview.platforms.qt',
]

excludes = [
    # Keep the bundle small — we don't need these even though some deps pull them in.
    'tkinter',
    'matplotlib',
    'numpy',
    'pandas',
    'scipy',
    'PIL',
    'setuptools',
    'pip',
    'pkg_resources',
]

a = Analysis(
    [str(ROOT / 'vortex_wizard' / '__main__.py')],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# Platform-appropriate icon
_icns = ROOT / 'vortex_wizard' / 'web' / 'assets' / 'icon.icns'
_ico  = ROOT / 'vortex_wizard' / 'web' / 'assets' / 'favicon.ico'
_icon_path = str(_icns) if (sys.platform == 'darwin' and _icns.is_file()) else str(_ico)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='vortex-wizard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX compresses but can break on macOS; leave off for reliability
    console=False,      # windowed app (no console)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=_icon_path,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='vortex-wizard',
)

# macOS: wrap in .app bundle
if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='Vortex Wizard.app',
        icon=str(ROOT / 'vortex_wizard' / 'web' / 'assets' / 'icon.icns'),
        bundle_identifier='sol.vortexx.wizard',
        version='0.1.0',
        info_plist={
            'NSHighResolutionCapable': 'True',
            'LSUIElement': 'False',
            'CFBundleShortVersionString': '0.1.0',
            'CFBundleVersion': '0.1.0',
            'NSHumanReadableCopyright': 'Vortex — decentralized',
            'NSAppTransportSecurity': {
                'NSAllowsLocalNetworking': True,
            },
        },
    )
