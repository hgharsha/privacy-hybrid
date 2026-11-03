"""Phase 3: the machine-readable policy, PII-STANDARD.md and the detector must agree. A documented Tier 1 category may not
quietly become a lower-tier masking decision, and ordinary numbers must not be masked."""
import json
import re
from pathlib import Path

import pytest

from privhybrid import detect as D
from privhybrid.vault import NeedsApproval, Vault

ROOT = Path(__file__).resolve().parents[2]
POLICY = json.loads((ROOT / "src/privhybrid/pii_policy.json").read_text())
DOC = (ROOT / "PII-STANDARD.md").read_text()
SECTIONS = {int(m[1]): m[2] for m in re.finditer(r"## Tier (\d)[^\n]*\n(.*?)(?=\n## |\Z)", DOC, re.S)}
NAMES = [e["name"] for e in POLICY["entities"]]


def entity(name):
    return next(e for e in POLICY["entities"] if e["name"] == name)


@pytest.mark.parametrize("name", NAMES)
def test_detector_agrees_with_policy(name):
    e = entity(name)
    det = D.detect(e["sample"], dictionary=e.get("dictionary"))
    hits = [x for x in det.entities if x.kind in e["kinds"]]
    assert hits, f"{name}: no {e['kinds']} found in the sample"
    assert min(h.tier for h in hits) == e["tier"], f"{name}: documented tier {e['tier']}, detected {[h.tier for h in hits]}"


@pytest.mark.parametrize("name", NAMES)
def test_document_lists_the_entity_in_the_right_tier(name):
    e = entity(name)
    section = SECTIONS[min(e["tier"], 3)]
    assert e["doc_phrase"].lower() in section.lower(), f"{name}: '{e['doc_phrase']}' not found under Tier {e['tier']} in PII-STANDARD.md"


@pytest.mark.parametrize("name", [n for n in NAMES if entity(n)["tier"] == 1])
def test_tier_1_blocks_instead_of_masking(name):
    e = entity(name)
    with pytest.raises(NeedsApproval):
        Vault(e.get("dictionary") or {}).mask(e["sample"] + " and some ordinary words around it.")


@pytest.mark.parametrize("name", [n for n in NAMES if entity(n)["tier"] in (2, 3)])
def test_lower_tiers_become_placeholders_not_raw_text(name):
    e = entity(name)
    text, counts = Vault(e.get("dictionary") or {}).mask(e["sample"] + ". " + "Plain filler words about the weather and the garden. " * 6)
    assert counts, f"{name}: nothing was masked"
    assert e["masking"].split("_")[0].strip("[") in text or "[" in text


@pytest.mark.parametrize("q", POLICY["quasi_identifiers"], ids=lambda q: q["name"])
def test_combinations_are_flagged(q):
    assert q["flag"] in D.detect(q["sample"], dictionary=q.get("dictionary")).quasi


@pytest.mark.parametrize("text", POLICY["false_positives"])
def test_ordinary_numbers_are_not_masked(text):
    det = D.detect(text)
    assert not det.tier1 and not [e for e in det.sensitive if e.kind in ("SSN", "CARD", "BANKACCT", "ROUTING", "PHONE", "GOVID")], text


# --- assessment PH-001 / PH-002 regressions ---------------------------------------------------

@pytest.mark.parametrize("text", [
    "my passport is X1234567", "Passport number: 123456789", "passport no. AB1234567", "passport # is 12345678",
    "passport number is C01234567", "PASSPORT = K9876543",
])
def test_id_phrasings_block_the_request(text):
    with pytest.raises(NeedsApproval):
        Vault().mask(text)


@pytest.mark.parametrize("text,raw", [
    ("I live at 221B Baker Street, London", "221B Baker Street"),
    ("Post it to 23 Elm Close please", "23 Elm Close"),
    ("Ship to 12 rue de la Paix, Paris", "12 rue de la Paix"),
    ("Hauptstraße 5 in Berlin", "Hauptstraße 5"),
    ("Office: SW1A 2AA", "SW1A 2AA"),
    ("Toronto M5V 3L9", "M5V 3L9"),
])
def test_non_us_addresses_are_masked(text, raw):
    masked, _ = Vault().mask(text + ". Please summarise the attached letter about the new contract terms and the delivery schedule.")
    assert raw not in masked


@pytest.mark.parametrize("text", ["My passport expired last year", "Visit Paris in June", "The price is 12 dollars"])
def test_passport_and_address_rules_leave_ordinary_text_alone(text):
    assert Vault().mask(text)[0] == text


# --- assessment PH-003 regressions ------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "My social security number: zero seven eight, zero five, one one two zero",
    "ssn is nine one two - seven three - four three two one",
    "Reisepass Nr. C01X00T47", "numéro de passeport 12AB34567", "Mi pasaporte número XDA123456", "Führerschein Nr: B072RRE2I55",
])
def test_spelled_ssn_and_foreign_id_labels_block_the_request(text):
    with pytest.raises(NeedsApproval):
        Vault().mask(text)


def test_ordinary_number_words_and_labels_are_left_alone():
    v = Vault()
    text = "My social security office opened at nine, then one two three people came."
    assert v.mask(text)[0] == text


def test_mostly_non_latin_text_is_not_sent_to_the_cloud():
    from privhybrid import egress
    for text in ["我叫王小明，住在北京市朝阳区建国路八十八号，请帮我写一封信。" * 2, "اسمي أحمد وأسكن في شارع النيل رقم خمسة في القاهرة" * 2]:
        with pytest.raises(NeedsApproval):
            egress._recheck_masked(text)


def test_a_few_foreign_words_in_english_text_are_fine():
    from privhybrid import egress
    egress._recheck_masked("The word 你好 means hello in Chinese, and it is one of the first phrases most learners pick up on day one.")
