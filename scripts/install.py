#!/usr/bin/env python3
"""Install privacy-hybrid for the current user: Python environment, start at login, and an app icon that opens it in its own window.

  python3 scripts/install.py              set up and register (Mac: launchd + app, Linux: systemd --user + menu entry, Windows: scheduled task + shortcut)
  python3 scripts/install.py --dry-run    print what would happen, change nothing
  python3 scripts/install.py --uninstall  remove the start-at-login entry and the app icon (your data in state/ is kept)

No admin rights and no sudo. Ollama is not installed here: get it from https://ollama.com first (this script checks and tells you).
Linux and Windows support is best effort: Mac and Ubuntu are the tested systems.
"""
import argparse
import os
import platform
import shutil
import subprocess
import time
import sys
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent.parent
LABEL = "local.privhybrid"
NAME = "Private Assistant"
SYSTEM = platform.system()  # Darwin | Linux | Windows


def venv_python(root: Path = ROOT, system: str = SYSTEM) -> Path:
    return root / ".venv" / ("Scripts/python.exe" if system == "Windows" else "bin/python")


def env_for(root: Path, bind: str, scheduler: bool, port: str = "8765", metrics: bool = False, tls: bool = False) -> dict:
    env = {"PYTHONPATH": str(root / "src"), "PRIVHYBRID_BIND": bind, "PRIVHYBRID_PORT": port}
    if scheduler:
        env["PRIVHYBRID_SCHEDULER"] = "1"
    if metrics:
        env["PRIVHYBRID_METRICS"] = "1"
    if tls:
        env["PRIVHYBRID_TLS_DIR"] = str(root / "state" / "tls")
    return env


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def launchd_plist(root: Path, bind: str, scheduler: bool, log: Path, system: str = "Darwin", port: str = "8765", metrics: bool = False, tls: bool = False) -> str:
    env = "".join(f"<key>{k}</key><string>{_esc(v)}</string>" for k, v in env_for(root, bind, scheduler, port, metrics, tls).items())
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{LABEL}</string>
<key>ProgramArguments</key><array><string>{_esc(str(venv_python(root, system)))}</string><string>-m</string><string>privhybrid.server</string></array>
<key>WorkingDirectory</key><string>{_esc(str(root))}</string>
<key>EnvironmentVariables</key><dict>{env}</dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>{_esc(str(log))}</string>
<key>StandardErrorPath</key><string>{_esc(str(log))}</string>
</dict></plist>
"""


def systemd_unit(root: Path, bind: str, scheduler: bool, system: str = "Linux", port: str = "8765", metrics: bool = False, tls: bool = False) -> str:
    env = "\n".join(f'Environment="{k}={v}"' for k, v in env_for(root, bind, scheduler, port, metrics, tls).items())
    return f"""[Unit]
Description={NAME} (privacy-hybrid)
After=network.target

[Service]
WorkingDirectory={root}
{env}
ExecStart="{venv_python(root, system)}" -m privhybrid.server
Restart=on-failure

[Install]
WantedBy=default.target
"""


def windows_runner(root: Path, bind: str, scheduler: bool, port: str = "8765", metrics: bool = False, tls: bool = False) -> str:
    lines = ["@echo off", f'cd /d "{root}"'] + [f"set {k}={v}" for k, v in env_for(root, bind, scheduler, port, metrics, tls).items()]
    return "\r\n".join(lines + [f'"{venv_python(root, "Windows")}" -m privhybrid.server', ""])


def browser_command(url: str, system: str = SYSTEM, which=shutil.which) -> Optional[List[str]]:
    """A Chromium-family browser in app mode (its own window, no tabs), or None: then the default browser is used."""
    if system == "Darwin":
        for app in ("Google Chrome", "Microsoft Edge", "Chromium", "Brave Browser"):
            if Path(f"/Applications/{app}.app").exists():
                return ["open", "-na", app, "--args", f"--app={url}"]
        return None
    names = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser") if system == "Linux" \
        else ("chrome", "msedge")
    for n in names:
        found = which(n)
        if found:
            return [found, f"--app={url}"]
    return None


def mac_app_script(url: str) -> str:
    cmd = browser_command(url, "Darwin")
    return "#!/bin/sh\n" + (" ".join(f"'{c}'" for c in cmd) if cmd else f"open '{url}'") + "\n"


def mac_info_plist() -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>{NAME}</string>
<key>CFBundleIdentifier</key><string>{LABEL}.app</string>
<key>CFBundleExecutable</key><string>launcher</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><false/>
<key>NSMicrophoneUsageDescription</key><string>Voice input for questions. Audio is turned into text on this Mac.</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
"""


def desktop_entry(url: str, icon: str = "") -> str:
    cmd = browser_command(url, "Linux")
    return f"""[Desktop Entry]
Type=Application
Name={NAME}
Comment=Private, local-first assistant
Exec={" ".join(cmd) if cmd else "xdg-open " + url}
Terminal=false
Categories=Utility;
{"Icon=" + icon + chr(10) if icon else ""}"""


def windows_launcher(url: str) -> str:
    cmd = browser_command(url, "Windows")
    return f'@echo off\r\n{" ".join(chr(34) + c + chr(34) if " " in c else c for c in cmd) if cmd else "start " + url}\r\n'


# --- actions ---------------------------------------------------------------------------------

class Runner:
    def __init__(self, dry: bool) -> None:
        self.dry = dry

    def say(self, msg: str) -> None:
        print(("[dry run] " if self.dry else "") + msg, flush=True)

    def run(self, cmd: List[str], check: bool = True, env: Optional[dict] = None) -> int:
        self.say("$ " + " ".join(cmd))
        if self.dry:
            return 0
        rc = subprocess.run(cmd, env={**os.environ, **env} if env else None).returncode
        if check and rc:
            sys.exit(f"Failed ({rc}): {' '.join(cmd)}")
        return rc

    def write(self, path: Path, text: str, mode: int = 0o644) -> None:
        self.say(f"write {path}")
        if not self.dry:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            path.chmod(mode)


SUPPORTED = ((3, 11), (3, 13))  # presidio-analyzer and spaCy pins: Python 3.11 to 3.13


def find_python(which=shutil.which, version=sys.version_info) -> List[str]:
    """The command that makes the venv: this Python if supported, else a supported one on PATH, else uv fetching one (no sudo)."""
    if SUPPORTED[0] <= tuple(version[:2]) <= SUPPORTED[1]:
        return [sys.executable, "-m", "venv"]
    for minor in (13, 12, 11, 10):
        found = which(f"python3.{minor}")
        if found:
            return [found, "-m", "venv"]
    if which("uv"):
        return ["uv", "venv", "--seed", "--python", "3.12"]
    sys.exit(f"Python {version[0]}.{version[1]} is not supported (3.11 to 3.13 is). Install Python 3.12, or install uv (https://docs.astral.sh/uv/) and run this again.")


def install_deps(r: Runner, skip: bool) -> None:
    py = venv_python()
    if not skip:
        if not py.exists():
            r.run(find_python() + [str(ROOT / ".venv")])
        r.run([str(py), "-m", "pip", "install", "--quiet", "--require-hashes", "-r", str(ROOT / "requirements.lock")])
        r.run([str(py), "-m", "pip", "install", "--quiet", "--require-hashes", "--no-deps", "-r", str(ROOT / "requirements-model.txt")])
    if not shutil.which("ollama"):
        r.say("Ollama was not found. Install it from https://ollama.com, then run: ollama pull gemma4:26b && ollama pull nomic-embed-text")


def build_mac_shell(r: Runner, app: Path, url: str) -> None:
    """A native window (WKWebView, its own process and cookies, no Chrome). Falls back to a Chromium app window without swiftc."""
    src = ROOT / "scripts" / "mac_shell.swift"
    if shutil.which("swiftc") and src.exists():
        r.write(app / "Resources/url.txt", url + "\n")
        ca = ROOT / "state" / "tls" / "ca.crt"
        if ca.exists():
            r.write(app / "Resources/ca.crt", ca.read_text())
        (app / "MacOS").mkdir(parents=True, exist_ok=True) if not r.dry else None
        if r.run(["swiftc", "-O", str(src), "-o", str(app / "MacOS/launcher")], check=False) == 0:
            r.run(["codesign", "--force", "--sign", "-", str(app.parent)], check=False)
            return
        r.say("The native window could not be built; using a browser app window instead.")
    else:
        r.say("swiftc was not found (run: xcode-select --install); using a browser app window instead.")
    r.write(app / "MacOS/launcher", mac_app_script(url), 0o755)


def install_mac(r: Runner, bind: str, scheduler: bool, url: str, port: str, metrics: bool = False, tls: bool = False) -> None:
    home = Path.home()
    plist = home / "Library/LaunchAgents" / f"{LABEL}.plist"
    r.write(plist, launchd_plist(ROOT, bind, scheduler, home / "Library/Logs/privhybrid.log", port=port, metrics=metrics, tls=tls))
    uid = str(os.getuid())
    r.run(["launchctl", "bootout", f"gui/{uid}/{LABEL}"], check=False)
    for _ in range(5):  # bootout is asynchronous; an immediate bootstrap can fail with I/O error 5
        if r.run(["launchctl", "bootstrap", f"gui/{uid}", str(plist)], check=False) == 0:
            break
        time.sleep(2)
    else:
        sys.exit("launchctl could not load the service; see ~/Library/Logs/privhybrid.log")
    app = home / "Applications" / f"{NAME}.app" / "Contents"
    r.write(app / "Info.plist", mac_info_plist())
    build_mac_shell(r, app, url)
    make_icns(r, ROOT / "static" / "mark.png", app / "Resources/AppIcon.icns")


def install_linux(r: Runner, bind: str, scheduler: bool, url: str, port: str, metrics: bool = False, tls: bool = False) -> None:
    home = Path.home()
    r.write(home / ".config/systemd/user/privhybrid.service", systemd_unit(ROOT, bind, scheduler, port=port, metrics=metrics, tls=tls))
    r.run(["systemctl", "--user", "daemon-reload"])
    r.run(["systemctl", "--user", "enable", "--now", "privhybrid.service"])
    r.write(home / ".local/share/applications/privhybrid.desktop", desktop_entry(url, str(ROOT / "static" / "mark.png")))
    r.say("To keep it running when you are logged out: loginctl enable-linger " + os.environ.get("USER", ""))


def install_windows(r: Runner, bind: str, scheduler: bool, url: str, port: str, metrics: bool = False, tls: bool = False) -> None:
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "privhybrid"
    r.write(base / "run.cmd", windows_runner(ROOT, bind, scheduler, port, metrics, tls))
    r.run(["schtasks", "/Create", "/F", "/SC", "ONLOGON", "/TN", "PrivacyHybrid", "/TR", f'"{base / "run.cmd"}"'])
    r.run(["schtasks", "/Run", "/TN", "PrivacyHybrid"], check=False)
    menu = Path(os.environ.get("APPDATA", str(Path.home()))) / "Microsoft/Windows/Start Menu/Programs"
    r.write(menu / f"{NAME}.cmd", windows_launcher(url))


def make_icns(r: Runner, png: Path, dest: Path) -> None:
    """Mac app icon from the PNG with the tools macOS ships (sips, iconutil). Skipped quietly if either is missing."""
    r.say(f"icon {dest}")
    if r.dry or not shutil.which("iconutil") or not png.exists():
        return
    import tempfile
    with tempfile.TemporaryDirectory() as t:
        iconset = Path(t) / "AppIcon.iconset"
        iconset.mkdir()
        for size in (16, 32, 128, 256, 512):
            for scale in (1, 2):
                name = f"icon_{size}x{size}{'@2x' if scale == 2 else ''}.png"
                subprocess.run(["sips", "-z", str(size * scale), str(size * scale), str(png), "--out", str(iconset / name)], capture_output=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(dest)], capture_output=True)


def make_tls(r: Runner, bind: str, renew: bool = False) -> None:
    """Create state/tls/ (ca.crt, server.crt, server.key) once; delete the folder to issue a new certificate (for example after the IP changes)."""
    folder = ROOT / "state" / "tls"
    if renew and folder.exists():
        r.say(f"tls: removing {folder} to issue a new certificate")
        if not r.dry:
            shutil.rmtree(folder)
    if (folder / "server.crt").exists():
        r.say(f"tls: keeping {folder} (delete it to issue a new certificate)")
        return
    r.run([str(venv_python(ROOT)), "-m", "privhybrid.tls", "--dir", str(folder), "--ip", bind], env={"PYTHONPATH": str(ROOT / "src")})
    r.say(f"Trust {folder / 'ca.crt'} on each device: Mac = double-click, Always Trust; iPhone = AirDrop it, install, then Settings > General > About > Certificate Trust Settings.")


def uninstall(r: Runner) -> None:
    home = Path.home()
    if SYSTEM == "Darwin":
        r.run(["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"], check=False)
        targets = [home / "Library/LaunchAgents" / f"{LABEL}.plist", home / "Applications" / f"{NAME}.app"]
    elif SYSTEM == "Linux":
        r.run(["systemctl", "--user", "disable", "--now", "privhybrid.service"], check=False)
        targets = [home / ".config/systemd/user/privhybrid.service", home / ".local/share/applications/privhybrid.desktop"]
    else:
        r.run(["schtasks", "/Delete", "/F", "/TN", "PrivacyHybrid"], check=False)
        local, roaming = os.environ.get("LOCALAPPDATA"), os.environ.get("APPDATA")
        targets = ([Path(local) / "privhybrid"] if local else []) + \
                  ([Path(roaming) / "Microsoft/Windows/Start Menu/Programs" / f"{NAME}.cmd"] if roaming else [])
    for t in targets:
        r.say(f"remove {t}")
        if not r.dry:
            shutil.rmtree(t, ignore_errors=True) if t.is_dir() else t.unlink(missing_ok=True)
    r.say("Done. Your data in state/ was not touched.")


def main(argv: Optional[List[str]] = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--skip-deps", action="store_true", help="the .venv is already set up")
    ap.add_argument("--no-autostart", action="store_true", help="set up the environment only")
    ap.add_argument("--metrics", action="store_true", help="serve /metrics for Prometheus to processes on this machine (PRIVHYBRID_METRICS=1)")
    ap.add_argument("--tls", action="store_true", help="HTTPS with a local certificate (makes state/tls/; trust ca.crt on each device)")
    ap.add_argument("--renew-tls", action="store_true", help="with --tls: issue a new certificate (after the IP changes or it expires); trust the new ca.crt on each device")
    ap.add_argument("--scheduler", action="store_true", help="turn on scheduled jobs (PRIVHYBRID_SCHEDULER=1)")
    ap.add_argument("--bind", default="127.0.0.1", help="address to listen on (127.0.0.1 = this computer only; a LAN address needs --tls)")
    ap.add_argument("--port", default="8765")
    a = ap.parse_args(argv)
    r = Runner(a.dry_run)
    if a.uninstall:
        return uninstall(r)
    if a.bind not in ("127.0.0.1", "::1", "localhost") and not a.tls:
        sys.exit("A network address needs HTTPS: add --tls (plain HTTP would send passwords and documents unencrypted)")
    url = f"{'https' if a.tls else 'http'}://{a.bind}:{a.port}/"
    install_deps(r, a.skip_deps)
    if a.tls:
        make_tls(r, a.bind, a.renew_tls)
    if not a.no_autostart:
        {"Darwin": install_mac, "Linux": install_linux, "Windows": install_windows}.get(SYSTEM, lambda *x: sys.exit(f"{SYSTEM} is not supported"))(r, a.bind, a.scheduler, url, a.port, a.metrics, a.tls)
    r.say(f"Ready: {url}  (register on the first visit)")


if __name__ == "__main__":
    main()
