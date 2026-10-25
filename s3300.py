"""Entry point for the offline COOLPIX S3300 development workspace."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from workspace_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
