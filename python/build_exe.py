import subprocess
import shutil
import sys
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
DIST_DIR = HERE / "dist"
BUILD_DIR = HERE / "build"
SPEC_FILE = HERE / "dzdbgport.spec"
MAIN_SCRIPT = HERE / "dzdbgport.py"
CACHE_FILE = HERE / ".build_hash"

def hash_source_files():
    """Generate a hash of all .py files in the project (including MAIN_SCRIPT)."""
    hasher = hashlib.sha256()
    for path in sorted(HERE.glob("**/*.py")):
        hasher.update(path.name.encode())
        hasher.update(path.read_bytes())
    return hasher.hexdigest()

def run(cmd, cwd=None):
    print(f"[cmd] {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)

def main():
    current_hash = hash_source_files()

    if CACHE_FILE.exists():
        previous_hash = CACHE_FILE.read_text()
        if current_hash == previous_hash:
            print("✅ No changes detected, skipping build.")
            return
        else:
            print("🔁 Changes detected, rebuilding...")

    print("🧹 Cleaning old build artifacts...")
    shutil.rmtree(DIST_DIR, ignore_errors=True)
    shutil.rmtree(BUILD_DIR, ignore_errors=True)
    if SPEC_FILE.exists():
        SPEC_FILE.unlink()

    print("📦 Installing dependencies via Poetry...")
    run(["poetry", "install"])

    print("🔨 Building binary with PyInstaller...")
    run([
        "poetry", "run", "pyinstaller",
        "--onefile", "--noconsole", "--windowed",
        "--name", "dzdbgport",
        str(MAIN_SCRIPT)
    ])

    binary_path = DIST_DIR / "dzdbgport.exe"
    if binary_path.exists():
        print(f"\n🎉 Build complete! Binary located at:\n  {binary_path}")
        CACHE_FILE.write_text(current_hash)
    else:
        print("❌ Build failed: no binary found.")

if __name__ == "__main__":
    main()