"""Locate web assets in a source checkout and in a flattened VPS installation."""
from pathlib import Path


def static_directory(runtime_root):
    root = Path(runtime_root)
    installed = root / 'static'
    source = root.parent / 'frontend' / 'static'
    if root.name == 'backend' and not installed.is_dir() and (source / 'index.html').is_file():
        return source
    return installed
