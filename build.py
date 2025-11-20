"""Build the Pentalfa Macro executable with PyInstaller and basic obfuscation."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_FILE = PROJECT_ROOT / "afspelen.py"
ASSETS = [PROJECT_ROOT / "afspelen.png"]
OUTPUT_NAME = "PentalfaMacro"
SPEC_FILE = PROJECT_ROOT / f"{OUTPUT_NAME}.spec"
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"


def ensure_pyinstaller() -> None:
    try:
        __import__("PyInstaller")  # noqa: WPS421
    except ModuleNotFoundError:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "pyinstaller"],
            check=True,
        )


def clean_previous_artifacts() -> None:
    for path in (DIST_DIR, BUILD_DIR):
        if path.exists():
            shutil.rmtree(path)
    if SPEC_FILE.exists():
        SPEC_FILE.unlink()


def _pyinstaller_supports_key() -> bool:
    try:
        import PyInstaller  # type: ignore
        from packaging import version

        return version.parse(PyInstaller.__version__) < version.parse("6.0")
    except Exception:
        return False


def build_executable() -> None:
    ensure_pyinstaller()
    clean_previous_artifacts()

    data_separator = ";" if os.name == "nt" else ":"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--noconsole",
        "--name",
        OUTPUT_NAME,
        "--optimize",
        "2",
    ]

    if _pyinstaller_supports_key():
        encryption_key = secrets.token_hex(16)
        cmd.insert(cmd.index("--name"), f"--key={encryption_key}")
    else:
        print(
            "PyInstaller >= 6 detected; skipping --key bytecode encryption (removed upstream). "
            "Consider layering additional obfuscation if required."
        )

    for asset in ASSETS:
        if not asset.exists():
            raise FileNotFoundError(f"Required asset not found: {asset}")
        cmd.extend(["--add-data", f"{asset}{data_separator}."])

    cmd.append(str(SOURCE_FILE))

    subprocess.run(cmd, check=True)

    print("Build complete.")
    print(f"  Executable: {DIST_DIR / (OUTPUT_NAME + '.exe') if os.name == 'nt' else DIST_DIR / OUTPUT_NAME}")


def main() -> None:
    build_executable()


if __name__ == "__main__":
    main()


