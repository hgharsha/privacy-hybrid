import json

from privhybrid import config, egress


def test_default_env_and_file(monkeypatch, tmp_path):
    f = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_FILE", f)
    for k in ("PRIVHYBRID_CHECK_MODEL", "PRIVHYBRID_OLLAMA_URL"):
        monkeypatch.delenv(k, raising=False)
    assert config.profile("check") == {"provider": "ollama", "model": config.DEFAULT_MODEL}
    f.write_text(json.dumps({"check": "llama3.1:8b", "ollama_url": "http://127.0.0.1:11435"}))
    assert config.profile("check")["model"] == "llama3.1:8b" and config.profile("check")["base_url"].endswith("11435")
    monkeypatch.setenv("PRIVHYBRID_CHECK_MODEL", "x:1")
    assert config.profile("check")["model"] == "x:1"
    f.write_text("not json")
    monkeypatch.delenv("PRIVHYBRID_CHECK_MODEL")
    assert config.profile("check")["model"] == config.DEFAULT_MODEL


def test_remote_ollama_url_is_still_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "none.json")
    monkeypatch.setenv("PRIVHYBRID_OLLAMA_URL", "http://8.8.8.8:11434")
    import pytest
    with pytest.raises(egress.EgressBlocked):
        egress._check_profile("local", config.profile("answer"))


def test_save_validates_and_persists(monkeypatch, tmp_path):
    import pytest
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "state" / "config.json")
    for k in ("PRIVHYBRID_ANSWER_MODEL", "PRIVHYBRID_OLLAMA_URL"):
        monkeypatch.delenv(k, raising=False)
    config.save({"answer": "qwen3:30b", "ollama_url": "http://localhost:11434/"})
    cur = config.current()
    assert cur["answer"] == "qwen3:30b" and cur["ollama_url"] == "http://localhost:11434" and not cur["answer_env"]
    with pytest.raises(ValueError):
        config.save({"ollama_url": "http://8.8.8.8:11434"})
    with pytest.raises(ValueError):
        config.save({"answer": "bad name; rm -rf"})
    assert config.current()["answer"] == "qwen3:30b"


def test_lan_and_backup_addresses(monkeypatch, tmp_path):
    import pytest
    from privhybrid import providers
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "state" / "config.json")
    for k in ("PRIVHYBRID_OLLAMA_URL", "PRIVHYBRID_OLLAMA_BACKUPS"):
        monkeypatch.delenv(k, raising=False)
    assert not providers.is_local_url("http://192.168.1.20:11434")  # nothing listed yet
    config.save({"ollama_url": "http://192.168.1.20:11434", "ollama_backups": "http://10.0.0.5:11434\nhttp://127.0.0.1:11434"})
    assert providers.is_local_url("http://192.168.1.20:11434") and providers.is_local_url("http://10.0.0.5:11434")
    assert not providers.is_local_url("http://192.168.1.20:9999") and not providers.is_local_url("http://192.168.1.21:11434")
    prof = config.profile("answer")
    assert prof["fallback_urls"] == "http://10.0.0.5:11434,http://127.0.0.1:11434"
    egress._check_profile("local", prof)
    with pytest.raises(egress.EgressBlocked):  # the free-model gateway stays on this machine
        egress._check_profile("freellm", {"provider": "ollama", "model": "m", "base_url": "http://192.168.1.20:11434"})
    for bad in ("http://example.com:11434", "http://8.8.8.8:11434", "http://user:pw@10.0.0.5:11434", "http://10.0.0.5:11434/x", "file:///etc/hosts"):
        with pytest.raises(ValueError):
            config.save({"ollama_backups": bad})
    with pytest.raises(ValueError):
        config.save({"ollama_backups": ["http://10.0.0.1:1", "http://10.0.0.2:1", "http://10.0.0.3:1", "http://10.0.0.4:1"]})


def test_failover_to_backup(monkeypatch):
    from privhybrid import providers
    seen = []

    def call(p):
        seen.append(p["base_url"])
        if p["base_url"].endswith(":1"):
            raise providers.Unreachable("down")
        return "ok"
    monkeypatch.setattr(providers, "is_local_url", lambda u: True)
    monkeypatch.setattr(providers, "_reachable", lambda u: None)
    assert providers._with_fallbacks({"base_url": "http://10.0.0.1:1", "fallback_urls": "http://10.0.0.2:2"}, call) == "ok"
    assert seen == ["http://10.0.0.1:1", "http://10.0.0.2:2"]
    import pytest
    with pytest.raises(providers.Unavailable):
        providers._with_fallbacks({"base_url": "http://10.0.0.1:1"}, call)


def test_backup_model_override(monkeypatch, tmp_path):
    from privhybrid import providers
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "state" / "config.json")
    for k in ("PRIVHYBRID_OLLAMA_URL", "PRIVHYBRID_OLLAMA_BACKUPS"):
        monkeypatch.delenv(k, raising=False)
    config.save({"ollama_backups": "http://10.0.0.5:11434 qwen3.6:35b-a3b-nvfp4"})
    assert config.current()["ollama_backups"] == ["http://10.0.0.5:11434 qwen3.6:35b-a3b-nvfp4"]
    assert providers.fallbacks(config.profile("answer")) == [("http://10.0.0.5:11434", "qwen3.6:35b-a3b-nvfp4")]
    assert providers.fallbacks(config.profile("embed")) == [("http://10.0.0.5:11434", "")]  # embeddings keep their model
    seen = []
    monkeypatch.setattr(providers, "is_local_url", lambda u: True)
    monkeypatch.setattr(providers, "_reachable", lambda u: None)

    def call(p):
        seen.append(p["model"])
        if p["base_url"].endswith("11434") and "10.0.0.5" not in p["base_url"]:
            raise providers.Unreachable("down")
        return "ok"
    assert providers._with_fallbacks({"model": "gemma4:26b", "base_url": "http://127.0.0.1:11434", "fallback_urls": "http://10.0.0.5:11434|q:1"}, call) == "ok"
    assert seen == ["gemma4:26b", "q:1"]
    import pytest
    with pytest.raises(ValueError):
        config.save({"ollama_backups": "http://10.0.0.5:11434 bad;name"})


def test_other_machines_need_a_high_port_and_timeouts_do_not_fail_over(monkeypatch):
    import pytest
    from privhybrid import providers
    assert config.valid_ollama_url("http://192.168.1.20:11434") and config.valid_ollama_url("http://127.0.0.1:80")
    for bad in ("http://192.168.1.1", "http://192.168.1.1:80", "http://10.0.0.1:443", "http://10.0.0.1:22"):
        assert not config.valid_ollama_url(bad)
    monkeypatch.setattr(providers, "is_local_url", lambda u: True)
    monkeypatch.setattr(providers, "_reachable", lambda u: None)
    seen = []

    def slow(p):
        seen.append(p["base_url"])
        raise providers.Unavailable("did not answer in time")  # the first machine may still be working: do not resend elsewhere
    with pytest.raises(providers.Unavailable):
        providers._with_fallbacks({"base_url": "http://10.0.0.1:1111", "fallback_urls": "http://10.0.0.2:2222"}, slow)
    assert seen == ["http://10.0.0.1:1111"]


def test_address_must_be_exactly_scheme_host_port():
    for bad in ("http://192.168.1.5:3000#", "http://192.168.1.5:3000?", "http://192.168.1.5:3000;x", "http://192.168.1.5:3000#|m",
                "http://192.168.1.5:3000,http://10.0.0.1:2000", "http://192.168.1.5:3000 m", "http://192.168.1.5:3000/api"):
        assert not config.valid_ollama_url(bad), bad
    assert config.valid_ollama_url("http://[fd00::1]:11434") and config.valid_ollama_url("http://192.168.1.5:3000/")


def test_ipv6_literal_is_matched_in_canonical_form(monkeypatch, tmp_path):
    from privhybrid import providers
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "state" / "config.json")
    for k in ("PRIVHYBRID_OLLAMA_URL", "PRIVHYBRID_OLLAMA_BACKUPS"):
        monkeypatch.delenv(k, raising=False)
    config.save({"ollama_backups": "http://[FD00:0::1]:11434"})
    assert ("fd00::1", 11434) in config.lan_endpoints() and providers.is_local_url("http://[fd00::1]:11434")


def test_a_404_does_not_fail_over_and_the_serving_host_is_logged(monkeypatch):
    from privhybrid import providers
    monkeypatch.setattr(providers, "is_local_url", lambda u: True)
    monkeypatch.setattr(providers, "_reachable", lambda u: None)
    import pytest

    def missing(p):
        raise providers.BadReply("HTTP 404")
    with pytest.raises(providers.BadReply):
        providers._with_fallbacks({"base_url": "http://127.0.0.1:1", "fallback_urls": "http://10.0.0.2:2222"}, missing)
    ok = providers._with_fallbacks({"base_url": "http://127.0.0.1:1", "fallback_urls": "http://10.0.0.2:2222"},
                                   lambda p: providers.Reply("t", "ollama", "m", "local") if "10.0.0.2" in p["base_url"] else (_ for _ in ()).throw(providers.Unreachable("x")))
    assert ok.host == "10.0.0.2:2222"


def test_embeddings_can_run_on_their_own_machine_first(monkeypatch, tmp_path):
    from privhybrid import providers
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "state" / "config.json")
    for k in ("PRIVHYBRID_OLLAMA_URL", "PRIVHYBRID_OLLAMA_BACKUPS", "PRIVHYBRID_EMBED_URL"):
        monkeypatch.delenv(k, raising=False)
    config.save({"embed_url": "http://10.0.0.5:11434", "ollama_backups": "http://10.0.0.6:11434 q:1"})
    emb, ans = config.profile("embed"), config.profile("answer")
    assert emb["base_url"] == "http://10.0.0.5:11434" and emb["fallback_urls"] == "http://127.0.0.1:11434,http://10.0.0.6:11434"
    assert "base_url" not in ans and ans["fallback_urls"] == "http://10.0.0.6:11434|q:1"
    assert providers.is_local_url("http://10.0.0.5:11434")
    import pytest
    with pytest.raises(ValueError):
        config.save({"embed_url": "http://10.0.0.5:80"})
    config.save({"embed_url": ""})
    assert config.profile("embed").get("base_url", "http://127.0.0.1:11434") == "http://127.0.0.1:11434"
