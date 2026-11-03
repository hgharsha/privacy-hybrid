"""V3: strict local-only mode. A listed Ollama on another computer is refused under Extreme privacy or PRIVHYBRID_LOCAL_ONLY=1, and every
application-managed external route respects Extreme privacy. No real network is used."""
import pytest

from privhybrid import config, egress, providers
from privhybrid.vault import Vault

LAN = "http://192.168.1.20:11434"


@pytest.fixture
def listed(monkeypatch):
    monkeypatch.setattr(config, "lan_endpoints", lambda: {("192.168.1.20", 11434)})
    monkeypatch.delenv("PRIVHYBRID_LOCAL_ONLY", raising=False)


def test_listed_lan_ollama_is_allowed_by_default_but_never_silently_in_strict_mode(listed, monkeypatch):
    assert providers.is_local_url(LAN)  # the explicit, documented configuration still works
    monkeypatch.setenv("PRIVHYBRID_LOCAL_ONLY", "1")
    assert not providers.is_local_url(LAN)
    assert providers.is_local_url("http://127.0.0.1:11434")  # local Ollama keeps working


def test_extreme_privacy_refuses_a_listed_remote_ollama(listed):
    with egress.bound(lambda: True, lambda kind: True):
        assert not providers.is_local_url(LAN) and providers.is_local_url("http://localhost:11434")
        with pytest.raises(egress.EgressBlocked):
            egress.send("local", [{"role": "user", "content": "hello there"}], Vault(), profile={"provider": "ollama", "base_url": LAN, "model": "m"})


def test_unreadable_policy_counts_as_strict(listed):
    def broken():
        raise RuntimeError("cannot read")
    with egress.bound(broken, lambda kind: True):
        assert not providers.is_local_url(LAN)


def test_connection_guard_also_refuses_the_listed_address_in_strict_mode(listed, monkeypatch):
    import socket
    monkeypatch.setenv("PRIVHYBRID_LOCAL_ONLY", "1")
    assert egress._allowed(socket.socket(), ("192.168.1.20", 11434)) is False
    monkeypatch.delenv("PRIVHYBRID_LOCAL_ONLY")
    assert egress._allowed(socket.socket(), ("192.168.1.20", 11434)) is True


@pytest.mark.parametrize("route", ["claude", "search"])
def test_every_external_route_stops_under_extreme(route):
    with egress.bound(lambda: True, lambda kind: True):
        with pytest.raises(egress.PolicyBlocked):
            if route == "claude":
                egress.send("claude", [{"role": "user", "content": "hello there"}], Vault(), profile={"provider": "openai_compat", "base_url": "https://api.example.com/v1", "model": "m", "api_key": "k"}, checker=lambda t: [])
            else:
                egress.search("weather in Paris")
