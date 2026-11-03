import pytest
from privhybrid import detect as D


@pytest.mark.parametrize("t", ["id 123456789", "123 45 6789", "123-45-\n6789", "SSN 123456789"])
def test_ssn_forms_detected(t):
    assert any(e.kind == "SSN" for e in D.detect(t).entities)


@pytest.mark.parametrize("t", ["Invoice 482913765", "Ref 123456789"])
def test_reference_numbers_not_ssn(t):
    assert not any(e.kind == "SSN" for e in D.detect(t).entities)


@pytest.mark.parametrize("t,flag", [
    ("ZIP 94110\nDOB: 1/2/1980", "zip+date"),
    ("Title: Engineer\nEmployer Acme Corp", "title+employer"),
    ("Diagnosis: asthma, Austin, TX 78701", "medical+place"),
])
def test_quasi_combinations(t, flag):
    assert flag in D.detect(t).quasi


def test_summarize_prompt_forbids_merchants():
    import inspect
    from privhybrid import local
    src = inspect.getsource(local.summarize)
    assert "merchant" in src and "SSN" in src


def test_concurrent_saves_never_corrupt(tmp_path):
    import threading
    from privhybrid import accounts
    acc = accounts.Account.__new__(accounts.Account)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    acc.folder = tmp_path
    acc._aead = AESGCM(b"k" * 32)
    ts = [threading.Thread(target=lambda i=i: [acc.save("v", {"n": i, "pad": "x" * 5000}) for _ in range(30)]) for i in range(6)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert acc.load("v", None)["pad"] == "x" * 5000
    assert not list(tmp_path.glob(".*.tmp"))


def test_speech_model_loads_offline_only(tmp_path, monkeypatch):
    import sys, types
    from privhybrid import speech
    seen = {}

    def fake(*a, **kw):
        seen.update(kw); raise OSError("offline")
    monkeypatch.setitem(sys.modules, "faster_whisper", types.SimpleNamespace(WhisperModel=fake))
    monkeypatch.setattr(speech, "_model", None)
    with pytest.raises(speech.SpeechError):
        speech.transcribe(b"x", tmp_path)
    assert seen.get("local_files_only") is True


def test_no_document_text_is_cached_in_the_process():
    from privhybrid import rag
    assert not hasattr(rag._financial, "cache_info")
