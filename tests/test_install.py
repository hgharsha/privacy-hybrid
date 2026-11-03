import pytest
import json
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("install", Path(__file__).resolve().parent.parent / "scripts" / "install.py")
inst = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inst)
ROOT = Path("/opt/my apps/privacy-hybrid")


def test_systemd_unit_quotes_paths_with_spaces_and_sets_env():
    u = inst.systemd_unit(ROOT, "127.0.0.1", True)
    assert 'ExecStart="/opt/my apps/privacy-hybrid/.venv/bin/python" -m privhybrid.server' in u
    assert 'Environment="PRIVHYBRID_SCHEDULER=1"' in u and 'Environment="PRIVHYBRID_BIND=127.0.0.1"' in u
    assert "WorkingDirectory=/opt/my apps/privacy-hybrid\n" in u  # systemd takes this path unquoted
    assert "PRIVHYBRID_SCHEDULER" not in inst.systemd_unit(ROOT, "127.0.0.1", False)


def test_launchd_plist_escapes_and_keeps_alive():
    p = inst.launchd_plist(Path("/Users/a&b/app"), "127.0.0.1", False, Path("/tmp/x.log"))
    assert "/Users/a&amp;b/app/.venv/bin/python" in p and "<key>KeepAlive</key><true/>" in p and "RunAtLoad" in p


def test_windows_runner_uses_scripts_python_and_env():
    r = inst.windows_runner(Path("C:/app"), "127.0.0.1", False, "9000")
    assert "Scripts" in r and "set PRIVHYBRID_PORT=9000" in r and r.endswith("\r\n")


def test_browser_app_mode_and_fallback():
    assert inst.browser_command("http://x/", "Linux", which=lambda n: "/usr/bin/chromium" if n == "chromium" else None) == ["/usr/bin/chromium", "--app=http://x/"]
    assert inst.browser_command("http://x/", "Linux", which=lambda n: None) is None
    assert "xdg-open http://x/" in inst.desktop_entry("http://x/") or "--app=" in inst.desktop_entry("http://x/")


def test_dry_run_changes_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    inst.main(["--dry-run", "--skip-deps"])
    assert not any(tmp_path.iterdir()) and "[dry run]" in capsys.readouterr().out


def test_python_choice_prefers_supported_then_path_then_uv(monkeypatch):
    ok = (3, 12, 1)
    assert inst.find_python(which=lambda n: None, version=ok)[1:] == ["-m", "venv"]
    assert inst.find_python(which=lambda n: "/usr/bin/python3.12" if n == "python3.12" else None, version=(3, 14, 0)) == ["/usr/bin/python3.12", "-m", "venv"]
    assert inst.find_python(which=lambda n: "/bin/uv" if n == "uv" else None, version=(3, 14, 0)) == ["uv", "venv", "--seed", "--python", "3.12"]
    import pytest
    with pytest.raises(SystemExit):
        inst.find_python(which=lambda n: None, version=(3, 14, 0))


def test_metrics_flag_sets_env_only_when_asked():
    assert "PRIVHYBRID_METRICS" not in inst.env_for(Path("/r"), "127.0.0.1", False)
    assert inst.env_for(Path("/r"), "127.0.0.1", False, metrics=True)["PRIVHYBRID_METRICS"] == "1"


def test_alert_notifier_reports_each_firing_alert_once():
    spec2 = importlib.util.spec_from_file_location("notify", Path(__file__).resolve().parent.parent / "observability" / "notify.py")
    nt = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(nt)
    body = json.dumps({"data": {"alerts": [{"state": "firing", "labels": {"alertname": "OllamaDown"}, "annotations": {"summary": "down"}},
                                           {"state": "pending", "labels": {"alertname": "SearchDown"}}]}})
    now = nt.firing(lambda: body)
    assert now == {"OllamaDown": "down"}
    assert nt.new_alerts(now, set()) == [("OllamaDown", "down")] and nt.new_alerts(now, {"OllamaDown"}) == []


def test_icon_is_wired_into_mac_app_and_desktop_entry():
    assert "<key>CFBundleIconFile</key><string>AppIcon</string>" in inst.mac_info_plist()
    assert "Icon=/x/mark.png" in inst.desktop_entry("http://127.0.0.1:8765/", "/x/mark.png")
    assert "Icon=" not in inst.desktop_entry("http://127.0.0.1:8765/")


def test_tls_flag_sets_env_dir_only_when_asked():
    assert "PRIVHYBRID_TLS_DIR" not in inst.env_for(Path("/r"), "127.0.0.1", False)
    assert inst.env_for(Path("/r"), "127.0.0.1", False, tls=True)["PRIVHYBRID_TLS_DIR"] == "/r/state/tls"


def test_tls_certificate_is_made_after_the_environment_exists(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(inst, "ROOT", tmp_path)
    inst.main(["--dry-run", "--tls", "--no-autostart"])
    out = capsys.readouterr().out
    assert out.index("pip install") < out.index("privhybrid.tls")


def test_mac_native_shell_is_wired_in():
    from pathlib import Path
    src = (Path(inst.ROOT) / "scripts" / "mac_shell.swift").read_text()
    assert "WKWebView" in src and "ca.crt" in src and "NSWorkspace.shared.open" in src  # local pages only; other links go to the browser
    assert "NSMicrophoneUsageDescription" in inst.mac_info_plist()


def test_network_bind_without_tls_is_refused():
    with pytest.raises(SystemExit):
        inst.main(["--dry-run", "--no-autostart", "--bind", "192.168.1.50"])
