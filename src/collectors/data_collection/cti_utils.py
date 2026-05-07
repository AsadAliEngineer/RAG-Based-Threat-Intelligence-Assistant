import json
from pathlib import Path
from typing import Any
import pandas as pd

def write_json(data: Any, path: Path) -> None:
    """Write data as JSON to the given path."""
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def safe_str(val: Any) -> str:
    """Convert a value to string, handling pandas NA values."""
    return str(val).strip() if pd.notna(val) else ""

def ensure_dir(path: Path) -> None:
    """Ensure a directory exists."""
    path.mkdir(parents=True, exist_ok=True) 