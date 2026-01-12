import os
import shutil
from pathlib import Path

def clean_pycache(root_dir="."):
    """
    Recursively deletes all __pycache__ directories and .pyc files.
    """
    print(f"[*] Starting cleanup in: {os.path.abspath(root_dir)}")
    
    count_dirs = 0
    count_files = 0
    
    for root, dirs, files in os.walk(root_dir):
        # Clean __pycache__ directories
        if "__pycache__" in dirs:
            pycache_path = Path(root) / "__pycache__"
            try:
                shutil.rmtree(pycache_path)
                print(f"  [+] Deleted directory: {pycache_path}")
                count_dirs += 1
            except Exception as e:
                print(f"  [!] Failed to delete {pycache_path}: {e}")
        
        # Clean .pyc and .pyo files just in case
        for file in files:
            if file.endswith((".pyc", ".pyo")):
                file_path = Path(root) / file
                try:
                    os.remove(file_path)
                    print(f"  [+] Deleted file: {file_path}")
                    count_files += 1
                except Exception as e:
                    print(f"  [!] Failed to delete {file_path}: {e}")

    print(f"\n[+] Cleanup complete!")
    print(f"  - Directories removed: {count_dirs}")
    print(f"  - Files removed: {count_files}")

if __name__ == "__main__":
    clean_pycache()
