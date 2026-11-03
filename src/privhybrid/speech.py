"""Speech to text on this Mac. The audio is decoded and transcribed here and is never stored or sent anywhere."""
import os
import tempfile
import threading
from pathlib import Path
from typing import Optional

MODEL = os.environ.get("PRIVHYBRID_WHISPER", "small")  # ~460 MB int8; "base" is faster and rougher
MAX_AUDIO = 6 * 1024 * 1024
_LOCK = threading.Lock()  # one clip at a time: the model is big and the CPU is shared with the chat model
_model = None


class SpeechError(Exception):
    pass


def _load(root: Path):
    global _model
    if _model is None:
        try:
            from faster_whisper import WhisperModel
        except ImportError:
            raise SpeechError("Speech to text is not installed on this Mac (pip install faster-whisper).")
        try:  # the app blocks outside network calls, so never ask HuggingFace: use the copy on disk
            _model = WhisperModel(MODEL, device="cpu", compute_type="int8", download_root=str(root), local_files_only=True)
        except Exception:
            raise SpeechError("The speech model is not on this computer yet. Download it once with scripts/fetch_voice_model.py (about 460 MB), or switch Voice to phone dictation in Settings.")
    return _model


def transcribe(audio: bytes, root: Path, runner=None) -> str:
    """The words in a short recording (any format ffmpeg-style decoding handles: m4a, mp4, webm, wav)."""
    if not audio or len(audio) > MAX_AUDIO:
        raise SpeechError("The recording is empty or too long.")
    with _LOCK:
        if runner is not None:
            return runner(audio)
        model = _load(root)
        fd, name = tempfile.mkstemp(suffix=".audio")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(audio)
            segments, _ = model.transcribe(name, vad_filter=True, beam_size=1)
            return " ".join(s.text.strip() for s in segments).strip()
        except SpeechError:
            raise
        except Exception as exc:
            raise SpeechError(f"Could not read that recording ({type(exc).__name__}).")
        finally:
            try:
                os.unlink(name)
            except OSError:
                pass
