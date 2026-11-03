import numpy as np
import pytest

from privhybrid import accounts, rag


def fake_embed(prof, texts, timeout=120):
    # "bank" texts point one way, "garden" texts another
    return [[1.0, 0.0] if "bank" in t.lower() else [0.0, 1.0] for t in texts]


def test_chunking_overlaps_and_covers_text():
    text = ("Sentence number one is here. " * 80).strip()
    parts = rag.chunk(text)
    assert len(parts) > 1 and all(len(p) <= rag.CHUNK for p in parts)
    assert parts[0][:20] in text and parts[-1][-20:] in text


def test_small_library_is_sent_whole():
    lib = [rag.build("a.txt", "short note", [], embedder=fake_embed)]
    assert [d.text for d in rag.select("anything", lib, embedder=fake_embed)] == ["short note"]


def test_large_library_returns_best_passages_by_meaning():
    bank = "The bank statement shows fees. " * 250
    garden = "Tomatoes grow in the garden beds. " * 120
    lib = [rag.build("bank.txt", bank, [], embedder=fake_embed), rag.build("garden.txt", garden, [], embedder=fake_embed)]
    got = rag.select("what did the bank charge?", lib, embedder=fake_embed, k=3)
    assert len(got) == 3 and all(d.name.startswith("bank.txt") for d in got)


def test_keyword_fallback_when_embeddings_fail():
    def down(prof, texts, timeout=120):
        raise rag.providers.Unavailable("down")
    bank = "The mortgage payment is due monthly. " * 120
    garden = "Tomatoes grow in the garden beds. " * 120
    lib = [rag.build("bank.txt", bank, [], embedder=down), rag.build("garden.txt", garden, [], embedder=down)]
    assert lib[0]["vecs"] == "" and "keyword" in lib[0]["notes"][-1]
    got = rag.select("when is the mortgage due", lib, embedder=down, k=2)
    assert all(d.name.startswith("bank.txt") for d in got)


def test_embeddings_refuse_an_outside_ollama(monkeypatch):
    monkeypatch.setenv("PRIVHYBRID_OLLAMA_URL", "http://8.8.8.8:11434")
    item = rag.build("a.txt", "x" * 50, [], embedder=fake_embed)
    assert item["vecs"] == ""  # blocked, fell back to keywords, nothing was sent


def test_embeddings_allow_a_listed_private_ollama(monkeypatch):
    monkeypatch.setenv("PRIVHYBRID_OLLAMA_URL", "http://10.0.0.5:11434")
    assert rag.build("a.txt", "x" * 50, [], embedder=fake_embed)["vecs"] != ""


def test_accounts_encrypt_and_reject_wrong_password(tmp_path):
    store = accounts.Store(tmp_path)
    acct = store.register("Me@Example.com", "a long password")
    acct.save("library.bin", [{"secret": "Northwind"}])
    assert b"Northwind" not in (tmp_path / acct.id / "library.bin").read_bytes()
    again = store.login("me@example.com", "a long password")
    assert again.load("library.bin", []) == [{"secret": "Northwind"}]
    with pytest.raises(accounts.AuthError):
        store.login("me@example.com", "another password")
    with pytest.raises(accounts.AuthError):
        store.register("me@example.com", "a long password")


def test_tampered_file_is_rejected(tmp_path):
    store = accounts.Store(tmp_path)
    acct = store.register("me@example.com", "a long password")
    acct.save("library.bin", [1])
    f = tmp_path / acct.id / "library.bin"
    raw = bytearray(f.read_bytes()); raw[-1] ^= 1; f.write_bytes(bytes(raw))
    with pytest.raises(accounts.AuthError):
        acct.load("library.bin", [])


def test_change_password_reencrypts_and_old_password_dies(tmp_path):
    store = accounts.Store(tmp_path)
    acct = store.register("me@example.com", "old password 1")
    acct.save("library.bin", [{"s": "Northwind"}])
    new = store.change_password(acct, "old password 1", "new password 2")
    assert new.load("library.bin", []) == [{"s": "Northwind"}]
    with pytest.raises(accounts.AuthError):
        store.login("me@example.com", "old password 1")
    assert store.login("me@example.com", "new password 2").load("library.bin", []) == [{"s": "Northwind"}]
    assert not (tmp_path / (acct.id + ".bak")).exists()


def test_wrong_old_password_changes_nothing(tmp_path):
    store = accounts.Store(tmp_path)
    acct = store.register("me@example.com", "old password 1")
    with pytest.raises(accounts.AuthError):
        store.change_password(acct, "guess guess 1", "new password 2")
    assert store.login("me@example.com", "old password 1")


def test_delete_account_removes_everything(tmp_path):
    store = accounts.Store(tmp_path)
    acct = store.register("me@example.com", "old password 1")
    with pytest.raises(accounts.AuthError):
        store.delete(acct, "wrong wrong 1")
    store.delete(acct, "old password 1")
    assert not acct.folder.exists()
    with pytest.raises(accounts.AuthError):
        store.login("me@example.com", "old password 1")


def _lib(**files):
    return [{"name": n, "text": t, "notes": [], "chunks": [t], "vecs": "", "dim": 0} for n, t in files.items()]


def test_small_library_keeps_only_the_files_the_question_names():
    lib = _lib(**{"fake_w4.txt": "Filing status single", "fake_bank_statement.txt": "Deposit 100",
                  "fake_credit_card_statement.txt": "Minimum payment 25", "general_notes.txt": "Lisbon trip: eat pasteis",
                  "Earlier chat: card spend": "You spent 50"})
    pick = lambda q: sorted(d.name for d in rag.select(q, lib))
    assert pick("Summarise my W-4 and bank statement for Claude") == ["fake_bank_statement.txt", "fake_w4.txt"]
    assert pick("What should I try to eat in Lisbon?") == ["general_notes.txt"]
    assert pick("How much is my minimum payment?") == ["fake_credit_card_statement.txt"]


def test_nothing_stands_out_keeps_everything():
    lib = _lib(**{"a.txt": "alpha", "b.txt": "beta"})
    assert len(rag.select("zzz qqq", lib)) == 2


def test_big_library_is_narrowed_to_named_files_before_searching():
    lib = _lib(**{"fake_w4.txt": "Filing status single " * 400, "general_notes.txt": "Lisbon trip " * 600})
    assert {d.name.split(" (")[0] for d in rag.select("What is on my W-4?", lib)} == {"fake_w4.txt"}


def test_embeddings_are_really_used_for_a_multi_chunk_library():
    def emb(prof, texts, timeout=120):  # "money" and "bank" mean the same thing here; the words themselves do not overlap
        return [[1.0, 0.0] if ("bank" in t.lower() or "money" in t.lower()) else [0.0, 1.0] for t in texts]
    bank = "The bank statement lists fees. " * 250
    garden = "Tomatoes grow in garden beds. " * 120
    lib = [rag.build("bank.txt", bank, [], embedder=emb), rag.build("garden.txt", garden, [], embedder=emb)]
    got = rag.select("money matters", lib, embedder=emb, k=3)
    assert len(got) == 3 and all(d.name.startswith("bank.txt") for d in got)


def test_backup_folder_is_not_an_account_and_register_race_is_clean(tmp_path):
    store = accounts.Store(tmp_path)
    acct = store.register("me@example.com", "a long password")
    (tmp_path / (acct.id + ".bak")).mkdir()
    (tmp_path / (acct.id + ".bak") / "meta.json").write_text("{}")
    assert store.count() == 1
    (tmp_path / "admin").unlink(missing_ok=True)
    assert store.admin_id() == acct.id


def test_admin_passes_on_when_the_admin_account_is_deleted(tmp_path):
    store = accounts.Store(tmp_path)
    first = store.register("one@example.com", "a long password")
    second = store.register("two@example.com", "a long password")
    assert store.admin_id() == first.id
    store.delete(first, "a long password")
    assert store.admin_id() == second.id


def test_a_folder_named_in_the_question_brings_its_files():
    lib = [{"name": "2022_transcript.pdf", "text": "alpha", "notes": [], "chunks": [], "folder": "Tax"},
           {"name": "scan0001.pdf", "text": "beta", "notes": [], "chunks": [], "folder": "Tax"},
           {"name": "recipes.txt", "text": "gamma", "notes": [], "chunks": [], "folder": ""}]
    got = rag.relevant("review the files in my tax folder", lib)
    assert [d["name"] for d in got] == ["2022_transcript.pdf", "scan0001.pdf"]
