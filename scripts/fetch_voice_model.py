"""One-time download of the speech model (about 460 MB for "small") into state/models.
The app itself never downloads anything; run this yourself, then use the microphone.
    .venv/bin/python scripts/fetch_voice_model.py
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODEL = os.environ.get("PRIVHYBRID_WHISPER", "small")
SIZES = {"tiny": "75 MB", "base": "145 MB", "small": "460 MB", "medium": "1.5 GB"}


def main() -> int:
    from faster_whisper.utils import download_model
    print(f"Downloading the '{MODEL}' speech model (about {SIZES.get(MODEL, 'several hundred MB')}) from HuggingFace to state/models ...")
    path = download_model(MODEL, cache_dir=str(ROOT / "state" / "models"))
    print(f"Done: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
