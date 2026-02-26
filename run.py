import os
import sys
import argparse
import subprocess
import webbrowser
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Running Vortex")
    parser.add_argument("--dev", action="store_true", help="Running in dev mode fastapi dev")
    parser.add_argument("--port", type=int, default=8000, help="Port for run: (default: 8000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host for tun: (default: 0.0.0.0)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")

    args = parser.parse_args()

    in_venv = sys.prefix != sys.base_prefix
    if not in_venv:
        print("⚠️  Warning: Virtual environment do not activated")

    try:
        import vortex_chat
        print(f"✅ Rust module loaded (version: {vortex_chat.VERSION})")
    except ImportError:
        print("❌ Rust module did not found. Packing...")
        try:
            subprocess.run(["maturin", "develop", "--release"], check=True)
            print("✅ Rust module packed successfully")
        except subprocess.CalledProcessError:
            print("❌ Error with packing rust module")
            print("Sure that maturin module installed")
            sys.exit(1)
        except FileNotFoundError:
            print("❌ maturin did not found!")
            sys.exit(1)

    if not args.no_browser:
        url = f"http://localhost:{args.port}"
        print(f"🌐 Opening browser: {url}")
        webbrowser.open(url)

    if args.dev:
        print(f"🚀 Running in dev mode (fastapi dev) on {args.host}:{args.port}")
        cmd = [
            "fastapi", "dev", "app/main.py",
            "--port", str(args.port),
            "--host", args.host
        ]
    else:
        print(f"🚀 Running in production mod (uvicorn) on {args.host}:{args.port}")
        cmd = [
            "uvicorn", "app.main:app",
            "--host", args.host,
            "--port", str(args.port),
            "--reload"
        ]

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n👋 Server was stopped")
    except FileNotFoundError:
        if args.dev:
            print("❌ fastapi did not found!")
        else:
            print("❌ uvicorn did not found!")
        sys.exit(1)

if __name__ == "__main__":
    main()