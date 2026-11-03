import pytest

from privhybrid import server


@pytest.mark.parametrize("host", ["0.0.0.0", "8.8.8.8", "::", "::1x"[:2], "172.217.0.1"])
def test_bad_bind_addresses_refused(host):
    with pytest.raises(ValueError):
        server.check_bind(host)


@pytest.mark.parametrize("host", ["127.0.0.1", "192.168.1.50", "10.0.0.5"])
def test_allowed_bind_addresses(host):
    assert server.check_bind(host) == host


def test_lan_bind_requires_tls_or_flag(tmp_path, monkeypatch):
    monkeypatch.delenv("PRIVHYBRID_ALLOW_HTTP", raising=False)
    monkeypatch.delenv("PRIVHYBRID_TLS_DIR", raising=False)
    with pytest.raises(ValueError, match="HTTPS"):
        server.serve(port=0, host="192.168.1.50", data_dir=str(tmp_path / "u"), audit_path=str(tmp_path / "a.jsonl"), dictionary_path=str(tmp_path / "d.txt"))
