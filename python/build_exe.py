import subprocess
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DIST_DIR = HERE / "dist"
BUILD_DIR = HERE / "build"
SPEC_FILE = HERE / "dzdbgport.spec"  # Optional, auto-created by pyinstaller
MAIN_SCRIPT = HERE / "dzdbgport.py"

def run(cmd, cwd=None):
    print(f"[cmd] {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)

def main():
    print("✅ Cleaning old build artifacts...")
    shutil.rmtree(DIST_DIR, ignore_errors=True)
    shutil.rmtree(BUILD_DIR, ignore_errors=True)
    if SPEC_FILE.exists():
        SPEC_FILE.unlink()

    print("📦 Installing dependencies via Poetry...")
    run(["poetry", "install"])

    print("🔨 Building binary with PyInstaller...")
    run([
        "poetry", "run", "pyinstaller",
        "--onefile",
        "--name", "dzdbgport-server",
        str(MAIN_SCRIPT)
    ])

    binary_path = DIST_DIR / "dzdbgport-server.exe"
    if binary_path.exists():
        print(f"\n🎉 Build complete! Binary located at:\n  {binary_path}")
    else:
        print("❌ Build failed: no binary found.")

if __name__ == "__main__":
    main()
