"""Deterministic check: a value this account holds must not leave, however it is written (no model involved)."""
import pytest

from privhybrid import egress
from privhybrid.vault import NeedsApproval, Vault


def _vault():
    v = Vault({"Zorblax Industries": "ORG", "Quillfeather": "PERSON"})
    v.placeholder("PERSON", "Margaret Ellsworth")
    v.placeholder("ACCOUNT", "8812 4467 9031")
    return v


@pytest.mark.parametrize("text", [
    "Please email Margaret Ellsworth today",
    "MARGARET   ELLSWORTH wrote",
    "m-a-r-g-a-r-e-t e.l.l.s.w.o.r.t.h",
    "Marg​aret Ells‍worth",
    "Ｍａｒｇａｒｅｔ Ellsworth",
    "ref 881244679031 attached",
    "acct 8812-4467-9031",
    "Quillfeather asked",
    "our client Zorblax  Industries",
])
def test_known_value_is_found_in_any_spelling(text):
    assert _vault().leaks(text) >= 1


@pytest.mark.parametrize("text", [
    "What is the capital of France?",
    "[PERSON_1] opened [ACCOUNT_1]",
    "Margaret sent a note",        # only part of a known name
    "88124 is a number",
])
def test_unrelated_text_passes(text):
    assert _vault().leaks(text) == 0


def test_short_values_are_ignored():
    v = Vault()
    v.placeholder("PERSON", "Jo")
    assert v.leaks("Jo went home") == 0


def test_send_refuses_when_a_known_value_is_in_the_text():
    v = _vault()
    with pytest.raises(NeedsApproval) as e:
        egress._prepare("claude", [{"role": "user", "content": "Summarise the memo that Quillfeather wrote"}],
                        Vault({}), None) if False else egress._prepare(
            "claude", [{"role": "user", "content": "m-a-r-g-a-r-e-t e-l-l-s-w-o-r-t-h said hello"}], v, lambda t: [])
    assert "KNOWN" in e.value.kinds


def test_a_normal_masked_question_still_goes():
    v = Vault()
    out, _ = egress._prepare("claude", [{"role": "user", "content": "Explain compound interest simply"}], v, lambda t: [])
    assert out[0]["content"].startswith("Explain")
