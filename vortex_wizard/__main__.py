"""Allow `python -m vortex_wizard` and PyInstaller entry point."""
# Use absolute import so this file works both with `python -m vortex_wizard`
# AND when PyInstaller uses it as the entry script (where the running module
# name is `__main__`, not `vortex_wizard.__main__`).
from vortex_wizard.app import main

if __name__ == "__main__":
    raise SystemExit(main())
