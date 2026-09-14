import json
import os
import tempfile
from pathlib import Path
from typing import Any


def atomic_write_text(path: str | os.PathLike[str], content: str) -> None:
    """Write text to disk via a temp file and atomic replace."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=str(target.parent), encoding="utf-8") as tmp:
        tmp.write(content)
        tmp_name = tmp.name
    os.replace(tmp_name, target)


def atomic_write_json(path: str | os.PathLike[str], payload: Any) -> None:
    """Write JSON to disk via a temp file and atomic replace."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=str(target.parent), encoding="utf-8") as tmp:
        json.dump(payload, tmp, ensure_ascii=False, indent=2, sort_keys=True)
        tmp.write("\n")
        tmp_name = tmp.name
    os.replace(tmp_name, target)
