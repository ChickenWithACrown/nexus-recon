import os
import shutil
import subprocess
import sys
from pathlib import Path

def clean_build():
    """Clean up previous build artifacts."""
    build_dirs = ["build", "dist", "nexus_recon.spec"]
    for item in build_dirs:
        if os.path.exists(item):
            if os.path.isdir(item):
                shutil.rmtree(item)
            else:
                os.remove(item)

def build_executable():
    """Build the executable using PyInstaller."""
    # Create a single file executable
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "NexusRecon",
        "--icon=NUL",  # Replace with path to .ico file if you have one
        "--noconsole",  # Use --console if you want to see console output
        "--add-data", "README.md;.",
        "--add-data", "LICENSE;.",
        "netrecon.py"
    ]
    
    print("Building executable...")
    subprocess.run(cmd, check=True)

def create_release_archive():
    """Create a zip archive for the release."""
    import datetime
    import zipfile
    
    version = "1.0.0"  # You might want to get this from pyproject.toml
    timestamp = datetime.datetime.now().strftime("%Y%m%d")
    archive_name = f"NexusRecon-v{version}-{timestamp}"
    
    # Files to include in the release
    files_to_include = [
        "dist/NexusRecon.exe",
        "netrecon.py",
        "README.md",
        "LICENSE",
        "requirements.txt"
    ]
    
    # Create release directory if it doesn't exist
    os.makedirs("release", exist_ok=True)
    
    # Create zip file
    zip_path = f"release/{archive_name}.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in files_to_include:
            if os.path.exists(file):
                arcname = os.path.basename(file)
                zipf.write(file, arcname=arcname)
                print(f"Added {file} to release archive as {arcname}")
    
    print(f"\nRelease archive created: {zip_path}")
    return zip_path

def main():
    print("=== NexusRecon Release Builder ===")
    
    # Clean previous builds
    print("\nCleaning previous builds...")
    clean_build()
    
    # Build the executable
    try:
        build_executable()
    except subprocess.CalledProcessError as e:
        print(f"Error building executable: {e}")
        sys.exit(1)
    
    # Create release archive
    print("\nCreating release archive...")
    release_zip = create_release_archive()
    
    print("\nBuild process completed successfully!")
    print(f"Release package: {os.path.abspath(release_zip)}")

if __name__ == "__main__":
    main()
