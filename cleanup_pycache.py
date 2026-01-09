import os
import shutil
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def cleanup_pycache(root_dir):
    """
    Recursively remove all __pycache__ directories and .pyc files.
    """
    logging.info(f"Starting cleanup in: {root_dir}")
    
    count_dirs = 0
    count_files = 0
    
    for root, dirs, files in os.walk(root_dir):
        # Remove __pycache__ directories
        if '__pycache__' in dirs:
            pycache_path = os.path.join(root, '__pycache__')
            try:
                shutil.rmtree(pycache_path)
                logging.info(f"Removed directory: {pycache_path}")
                count_dirs += 1
            except Exception as e:
                logging.error(f"Failed to remove {pycache_path}: {e}")
        
        # Remove .pyc and .pyo files
        for file in files:
            if file.endswith('.pyc') or file.endswith('.pyo'):
                file_path = os.path.join(root, file)
                try:
                    os.remove(file_path)
                    logging.info(f"Removed file: {file_path}")
                    count_files += 1
                except Exception as e:
                    logging.error(f"Failed to remove {file_path}: {e}")

    logging.info("="*30)
    logging.info(f"Cleanup finished!")
    logging.info(f"Directories removed: {count_dirs}")
    logging.info(f"Files removed: {count_files}")
    logging.info("="*30)

if __name__ == "__main__":
    # Target current directory
    target_dir = os.path.dirname(os.path.abspath(__file__))
    cleanup_pycache(target_dir)
