import importlib.util
import pathlib

spec = importlib.util.spec_from_file_location("egress_watch", pathlib.Path(__file__).parent.parent / "observability" / "egress_watch.py")
W = importlib.util.module_from_spec(spec); spec.loader.exec_module(W)

HEAD = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"


def row(proc, name):
    return f"{proc} 1 u 8u IPv4 0x1 0t0 TCP {name}\n"


def test_local_and_lan_connections_are_fine():
    t = HEAD + row("ollama", "127.0.0.1:1->127.0.0.1:2 (ESTABLISHED)") + row("ollama", "192.168.1.5:11434->192.168.1.9:4000 (ESTABLISHED)")
    assert W.find_outside(t) == set()


def test_public_address_is_flagged_and_other_apps_are_ignored():
    t = HEAD + row("ollama", "192.168.1.5:1->104.18.1.1:443 (ESTABLISHED)") + row("Chrome", "192.168.1.5:1->8.8.8.8:443 (ESTABLISHED)")
    assert W.find_outside(t) == {("ollama", "104.18.1.1")}


def test_listen_lines_are_ignored():
    assert W.find_outside(HEAD + row("ollama", "*:11434 (LISTEN)")) == set()
