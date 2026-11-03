import pytest

from privhybrid import detect as D

# All fake. 4111... is the standard Visa test number; 021000021 is a valid ABA checksum.
TIER1 = {
    "SSN": "SSN: 123-45-6789",
    "SSN_nodash": "Social security number 123456789",
    "CARD": "card 4111 1111 1111 1111 exp 12/29",
    "CVV": "CVV: 123",
    "ROUTING": "routing number 021000021",
    "BANKACCT": "Account number 123456789012",
    "BANKACCT_dashed": "Checking account: 4400-8821-6637",
    "EIN_parens": "Employer identification number (EIN): 12-3456789",
    "IBAN": "pay GB82 WEST 1234 5698 7654 32 today",
    "GOVID": "Passport no: X1234567",
    "MEDID": "MRN: 00123456",
    "SECRET": "api_key = sk-or-v1-abcdefghijklmnopqrstuvwxyz0123",
    "SECRET_pw": "password: hunter2hunter2",
    "SECRET_otp": "your verification code is 482913",
}
TIER2 = {
    "EMAIL": "write to jane.doe@example.com",
    "PHONE": "call (415) 555-0171",
    "PHONE_intl": "call +1 415 555 0171",
    "DOB": "DOB: 03/14/1985",
    "ADDRESS": "lives at 742 Evergreen Terrace Ave, Apt 4",
    "ID": "username: jdoe1985",
}
TIER3 = {
    "AMOUNT": "Deposit of $4,250.00 posted",
    "TXN": "check #10452 cleared",
    "DATE": "posted 10/03/2026",
}


def kinds(text, **kw):
    return {(e.kind, e.tier) for e in D.detect(text, use_presidio=False, **kw).entities}


@pytest.mark.parametrize("name,text", TIER1.items())
def test_tier1_detected(name, text):
    det = D.detect(text, use_presidio=False)
    assert det.tier1, f"{name} not caught: {text}"


@pytest.mark.parametrize("name,text", TIER2.items())
def test_tier2_detected(name, text):
    assert any(t == 2 for _, t in kinds(text)), f"{name} not caught"


@pytest.mark.parametrize("name,text", TIER3.items())
def test_tier3_detected(name, text):
    assert any(t == 3 for _, t in kinds(text)), f"{name} not caught"


def test_checksums_reject_look_alikes():
    assert not D.detect("order 4111 1111 1111 1112", use_presidio=False).tier1  # fails Luhn
    assert not D.detect("routing 123456789", use_presidio=False).tier1  # fails ABA
    assert not D.detect("version 1.2.3.999", use_presidio=False).entities


def test_tier1_wins_overlap():
    det = D.detect("Account number 123456789012", use_presidio=False)
    assert [e.tier for e in det.entities] == [1]


def test_presidio_finds_names_and_orgs():
    det = D.detect("Jane Doe works at Acme Corporation in Austin.")
    found = {e.kind for e in det.entities}
    assert "PERSON" in found


def test_dictionary_catches_custom_terms(tmp_path):
    f = tmp_path / "dict.txt"
    f.write_text("ORG: Zorblax Industries  # employer\nMERCHANT: Joe's Corner Deli\n")
    d = D.load_dictionary(str(f))
    det = D.detect("paid Joe's  Corner Deli, employer zorblax industries", dictionary=d, use_presidio=False)
    assert {e.kind for e in det.entities} == {"MERCHANT", "ORG"}


def test_quasi_identifier_flag():
    det = D.detect("ZIP 78701, DOB: 03/14/1985", use_presidio=False)
    assert "zip+date" in det.quasi


def test_fail_closed_when_presidio_missing(monkeypatch):
    monkeypatch.setattr(D, "_analyzer", None)
    with pytest.raises(D.DetectorError):
        D.detect("hello", model="no_such_model")


def test_missing_dictionary_is_empty(tmp_path):
    assert D.load_dictionary(str(tmp_path / "nope.txt")) == {}


@pytest.mark.parametrize("q", ["Summarise my W-4 and bank statement for Claude", "What is on my 1099-INT?", "Ask Anthropic about Schedule C"])
def test_form_and_tool_names_are_not_people(q):
    assert not D.detect(q).entities


def test_real_names_next_to_form_names_still_masked():
    assert [e.text for e in D.detect("Maria Lopez filed a W-4").entities] == ["Maria Lopez"]
    assert D.detect("Claude", {"Claude": "PERSON"}).entities  # a user's own dictionary is never filtered


@pytest.mark.parametrize("text", ["change the name of the file", "Dear all, the customer service rep is out"])
def test_ordinary_words_after_a_name_keyword_are_not_a_person(text):
    assert not [e for e in D.detect(text).entities if e.kind == "PERSON"]


def test_name_after_keyword_is_still_found_without_the_filler_word():
    people = [e.text.strip(" ,") for e in D.detect("My name is Jane Doe and I live here").entities if e.kind == "PERSON"]
    assert any("Jane Doe" in p for p in people) and not any(p.startswith("is ") for p in people)


@pytest.mark.parametrize("text", ["Paid 1500 4111 1111 1111 1111 today", "2024-01-05 4111 1111 1111 1111", "ref 20240105 4111-1111-1111-1111 posted"])
def test_card_next_to_other_digits_is_still_tier_1(text):
    assert any(e.kind == "CARD" and e.tier == 1 for e in D.detect(text).entities)


def test_itin_is_tier_1_and_impossible_ssn_is_not():
    assert any(e.kind == "SSN" for e in D.detect("ITIN: 912-70-5678").entities)  # 9xx with a valid ITIN middle group
    assert not any(e.kind == "SSN" for e in D.detect("code 900-10-1234").entities)


def test_card_scan_stays_fast_on_a_long_column_of_numbers():
    import time
    line = " ".join(f"{i % 90 + 10}-{i % 77 + 10}" for i in range(1500))
    t = time.time()
    D.detect(line)
    assert time.time() - t < 10


def test_a_chance_match_in_front_does_not_hide_the_real_card():
    ents = D.detect("ref 1234 5678 9012 3456 then card 4111 1111 1111 1111 end").entities
    assert any(e.kind == "CARD" and e.text.replace(" ", "").endswith("4111111111111111") for e in ents)


def test_watch_flags_marks_what_the_filter_cannot_mask():
    from privhybrid.detect import watch_flags
    assert any("spelled" in f for f in watch_flags("my number is four one five five five five one two three four ok"))
    assert any("long number" in f for f in watch_flags("ref 1234 5678 9012 3456"))
    assert any("social security" in f for f in watch_flags("My Social Security number is on the form"))
    assert watch_flags("What is the weather like in [CITY_1] today, [PERSON_1]? It was 72 degrees.") == []
    assert watch_flags("one two three") == []  # a short run is ordinary prose
