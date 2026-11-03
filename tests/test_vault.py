import copy
import pickle

import pytest

from privhybrid.vault import NeedsApproval, Vault

SAMPLE = ("Deposit of $4,250.00 from Acme Corporation on 10/03/2026. Contact jane.doe@example.com or (415) 555-0171. "
          "Statement for Jane Doe, check #10452 cleared. Filler text so the sensitive share stays under the limit. " * 1)
LONG = SAMPLE + " The weather was mild and the report was short and clear. " * 12


def test_roundtrip_restores_everything():
    v = Vault()
    masked, counts = v.mask(LONG)
    for secret in ("jane.doe@example.com", "(415) 555-0171", "$4,250.00", "10452"):
        assert secret not in masked
    restored, unknown = v.unmask(masked)
    assert restored == LONG and unknown == []
    assert counts["EMAIL"] == 1 and counts["AMOUNT"] == 1


def test_stable_and_variant_placeholders():
    v = Vault()
    text = ("Call (415) 555-0171 or 415.555.0171 or +1 415 555 0171. " * 1 + "Jon Smith wrote; SMITH, JON replied. "
            + "Filler words here to dilute the share of sensitive text. " * 6)
    masked, _ = v.mask(text)
    assert masked.count("[PHONE_1]") == 3 and "[PHONE_2]" not in masked
    assert masked.count("[PERSON_1]") == 2


def test_distinct_values_get_distinct_placeholders():
    v = Vault()
    masked, _ = v.mask("a@example.com b@example.com " + "plain filler text goes here. " * 10)
    assert "[EMAIL_1]" in masked and "[EMAIL_2]" in masked


def test_tier1_raises_and_leaks_no_value():
    v = Vault()
    with pytest.raises(NeedsApproval) as exc:
        v.mask("SSN: 123-45-6789 " + "filler " * 40)
    assert "123-45-6789" not in str(exc.value) and exc.value.kinds == {"SSN": 1}
    assert len(v) == 0


def test_too_much_masked_raises():
    with pytest.raises(NeedsApproval):
        Vault().mask("jane.doe@example.com a@example.com")


def test_unknown_placeholder_is_flagged_not_guessed():
    v = Vault()
    v.mask("jane.doe@example.com " + "filler text. " * 20)
    out, unknown = v.unmask("Send to [EMAIL_1] and [PERSON_9].")
    assert out == "Send to jane.doe@example.com and [PERSON_9]." and unknown == ["[PERSON_9]"]


def test_literal_placeholder_in_input_is_not_confused():
    v = Vault()
    text = "The doc says [PERSON_1] twice. " + "filler text. " * 20
    masked, _ = v.mask(text)
    assert "[PERSON_1]" not in masked
    assert v.unmask(masked)[0] == text


def test_map_cannot_be_saved_or_printed():
    v = Vault()
    v.mask("jane.doe@example.com " + "filler text. " * 20)
    for fn in (pickle.dumps, copy.copy, copy.deepcopy):
        with pytest.raises(TypeError):
            fn(v)
    assert "jane" not in repr(v)


@pytest.mark.parametrize("size", [1, 2, 3, 5, 7])
def test_stream_split_anywhere_is_safe(size):
    v = Vault()
    v.mask("jane.doe@example.com " + "filler text. " * 20)
    reply = "Email [EMAIL_1] now, ask [PERSON_4], note [x] and [ open bracket"
    s = v.stream()
    shown = []
    for i in range(0, len(reply), size):
        piece = s.feed(reply[i:i + size])
        assert "[EMAIL" not in piece  # never a half or raw placeholder for a known one
        shown.append(piece)
    shown.append(s.flush())
    assert "".join(shown) == "Email jane.doe@example.com now, ask [PERSON_4], note [x] and [ open bracket"
    assert s.unknown == ["[PERSON_4]"]
