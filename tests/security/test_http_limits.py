"""Phase 8: slow or abusive clients cannot hold the server, and hostile uploads are bounded."""
import io
import json
import socket
import threading
import time
import zipfile

import pytest

from privhybrid import accounts, ingest, server


def start(tmp_path, monkeypatch, **consts):
    for k, v in consts.items():
        monkeypatch.setattr(server, k, v)
    httpd = server.serve(port=0, data_dir=str(tmp_path / "users"), audit_path=str(tmp_path / "a.jsonl"), dictionary_path=str(tmp_path / "d.txt"))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def conn(httpd):
    return socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=10)


def test_a_client_that_stops_sending_is_dropped(tmp_path, monkeypatch):
    httpd = start(tmp_path, monkeypatch, SOCKET_TIMEOUT=1)
    try:
        s = conn(httpd)
        s.sendall(b"POST /api/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n\r\n{\"email\"")  # promises 100 bytes, sends 8, then goes quiet
        t0 = time.time()
        s.settimeout(8)
        try:
            data = s.recv(100)
        except OSError:
            data = b""
        assert time.time() - t0 < 6, "the server kept waiting"
        assert b"200" not in data
    finally:
        httpd.shutdown()


def test_a_client_that_never_finishes_the_headers_is_dropped(tmp_path, monkeypatch):
    httpd = start(tmp_path, monkeypatch, SOCKET_TIMEOUT=1)
    try:
        s = conn(httpd)
        s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        t0 = time.time()
        assert s.recv(100) in (b"", ) or time.time() - t0 < 6
        assert time.time() - t0 < 6
    finally:
        httpd.shutdown()


def test_connections_over_the_limit_are_closed_at_once(tmp_path, monkeypatch):
    httpd = start(tmp_path, monkeypatch, MAX_CONNECTIONS=2)
    held = []
    try:
        held = [conn(httpd), conn(httpd)]
        for h in held:
            h.sendall(b"GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n")  # two slow clients holding both slots
        time.sleep(0.3)
        extra = conn(httpd)
        extra.settimeout(3)
        try:
            data = extra.recv(10)
        except OSError:
            data = b""
        assert data == b""  # closed, not served and not waiting
    finally:
        for h in held:
            h.close()
        httpd.shutdown()


def test_oversized_body_is_refused_before_reading(tmp_path, monkeypatch):
    httpd = start(tmp_path, monkeypatch)
    try:
        s = conn(httpd)
        s.sendall(f"POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:{httpd.server_address[1]}\r\nX-Requested-With: privhybrid\r\nContent-Length: {server.MAX_BODY + 1}\r\n\r\n".encode())
        assert b" 400 " in s.recv(200)
        s = conn(httpd)
        s.sendall(f"POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:{httpd.server_address[1]}\r\nX-Requested-With: privhybrid\r\nContent-Length: abc\r\n\r\n".encode())
        assert b" 400 " in s.recv(200)
    finally:
        httpd.shutdown()


def test_background_work_uses_a_bounded_pool():
    assert server.POOL._max_workers == server.BG_WORKERS <= 8


def zip_bytes(member, payload):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(member, payload)
    return b.getvalue()


def test_a_docx_zip_bomb_is_refused(monkeypatch):
    monkeypatch.setattr(ingest, "MAX_XML_BYTES", 1_000_000)
    bomb = zip_bytes("word/document.xml", b"<w:t>" + b"A" * 3_000_000 + b"</w:t>")
    assert len(bomb) < 100_000
    with pytest.raises(ingest.Unreadable):
        ingest.extract("bomb.docx", bomb)


def test_an_xlsx_zip_bomb_and_entity_tricks_are_refused(monkeypatch):
    monkeypatch.setattr(ingest, "MAX_XML_BYTES", 1_000_000)
    with pytest.raises(ingest.Unreadable):
        ingest.extract("bomb.xlsx", zip_bytes("xl/worksheets/sheet1.xml", b"<worksheet>" + b"A" * 3_000_000 + b"</worksheet>"))
    evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaaaaaaaa">]><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>'
    with pytest.raises(ingest.Unreadable):
        ingest.extract("evil.xlsx", zip_bytes("xl/worksheets/sheet1.xml", evil))


def test_malformed_archives_and_oversized_files_are_refused():
    for name in ("broken.docx", "broken.xlsx", "broken.pdf"):
        with pytest.raises(ingest.Unreadable):
            ingest.extract(name, b"this is not an archive")
    with pytest.raises(ingest.Unreadable):
        ingest.extract("big.txt", b"x" * (ingest.MAX_BYTES + 1))


def test_stale_temp_files_from_a_crash_are_cleaned_up(tmp_path):
    store = accounts.Store(tmp_path / "users")
    acct = store.register("a@example.com", "correct horse 1")
    old, fresh = acct.folder / ".library.bin.dead.tmp", acct.folder / ".library.bin.live.tmp"
    old.write_bytes(b"x"); fresh.write_bytes(b"x")
    past = time.time() - 7200
    import os
    os.utime(old, (past, past))
    accounts.Store(tmp_path / "users")
    assert not old.exists() and fresh.exists()


def raw_post(httpd, path, size, cookie=""):
    s = conn(httpd)
    head = f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{httpd.server_address[1]}\r\nX-Requested-With: privhybrid\r\nContent-Type: application/json\r\nContent-Length: {size}\r\nConnection: close\r\n{cookie}\r\n"
    s.sendall(head.encode())  # the body is never sent: a server that tries to read it would wait for it
    s.settimeout(5)
    out = b""
    try:
        while chunk := s.recv(4096):
            out += chunk
    except socket.timeout:
        pass
    s.close()
    return out


def test_signed_out_post_is_refused_before_the_body_is_read(tmp_path, monkeypatch):
    httpd = start(tmp_path, monkeypatch)
    try:
        assert b" 401 " in raw_post(httpd, "/api/chat", 1024 * 1024).split(b"\r\n")[0] + b" "
    finally:
        httpd.shutdown()


def test_sign_in_bodies_are_capped_small(tmp_path, monkeypatch):
    httpd = start(tmp_path, monkeypatch)
    try:
        assert b" 400 " in raw_post(httpd, "/api/login", 1024 * 1024).split(b"\r\n")[0] + b" "
    finally:
        httpd.shutdown()


def test_many_addresses_guessing_one_account_hit_an_account_wide_delay(tmp_path, monkeypatch):
    httpd = start(tmp_path, monkeypatch)
    try:
        app = httpd.app
        for i in range(server.ACCOUNT_FAILS_PER_MINUTE):  # twenty different peers, one failure each
            app.fail("acct|victim")
        assert app.locked_out("acct|victim", limit=server.ACCOUNT_FAILS_PER_MINUTE)
        assert not app.locked_out("10.0.0.9")  # another address is not affected by the per-address rule
    finally:
        httpd.shutdown()
