import importlib.util
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_dashboard", ROOT / "scripts/build_dashboard.py")
bd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bd)


def test_dashboard_counts_match_the_tracker():
    data = bd.rows(bd.TRACKER.read_text())
    assert len(data) >= 20
    page = bd.build()
    for name, n in Counter(bd.status_group(r["Status"]) for r in data).items():
        assert f"{name} <b>{n}</b>" in page
    assert all(r["ID"] in page for r in data)


def test_dashboard_is_self_contained():
    page = bd.build()
    assert "<script" not in page
    assert "src=\"http" not in page.replace("https://github.com/hgharsha/privacy-hybrid/actions", "")
