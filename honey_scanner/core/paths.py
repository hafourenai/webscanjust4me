import os
import sys
from pathlib import Path

def get_package_root() -> Path:
    """Returns the root directory of the honey_scanner package."""
    return Path(__file__).parent.parent.absolute()

def get_project_root() -> Path:
    """Returns the root directory of the project (where pyproject.toml usually is)."""
    return get_package_root().parent

def get_resources_dir() -> Path:
    """Returns the path to the resources directory."""
    return get_package_root() / "resources"

def get_payloads_dir() -> Path:
    """Returns the path to the internalized payloads directory."""
    return get_resources_dir() / "payloads"

def get_default_logs_dir() -> Path:
    """Returns the default directory for logs."""
    return get_project_root() / "logs"

def get_default_reports_dir() -> Path:
    """Returns the default directory for reports."""
    return get_project_root() / "reports"

def ensure_dirs():
    """Ensures that default logs and reports directories exist."""
    get_default_logs_dir().mkdir(parents=True, exist_ok=True)
    get_default_reports_dir().mkdir(parents=True, exist_ok=True)

def find_config(custom_path: str = None) -> Path:
    """
    Search for config.yaml in multiple locations:
    1. Custom path if provided
    2. Current Working Directory
    3. Project Root
    4. Package Root
    """
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p

    search_paths = [
        Path.cwd() / "config.yaml",
        get_project_root() / "config.yaml",
        get_package_root() / "config.yaml"
    ]

    for path in search_paths:
        if path.exists():
            return path
            
    return None
