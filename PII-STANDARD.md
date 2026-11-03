# PII standard for the privacy gate

Date: 2026-10-27. **Status: conditionally approved by the owner (2026-10-27), pending their full review.** Changes allowed after review; build against it meanwhile. Defines what the gate must treat as sensitive. Modeled on NIST SP 800-122 (PII), GLBA "nonpublic personal information", PCI DSS (card data) and the HIPAA identifier list. This is a working engineering standard, not legal advice.

## Rule
Anything in tiers 1 to 3 never leaves this Mac in raw form. Tier 4 is also masked for FreeLLMAPI. Transactions (amounts + merchant + date tied to a person's account) count as PII as a whole, not only their identifiers.

## Tier 1: block, never sent, not even as placeholders
Secrets and credentials. If found, stop and ask.
| Entity | Detection |
|---|---|
| SSN / ITIN | regex `\d{3}-?\d{2}-?\d{4}` with area/group validity checks |
| Full card number (PAN), CVV, expiry with PAN | 13-19 digits + Luhn check |
| Bank account + routing number | 8-17 digits near "account/acct/routing/ABA"; routing: 9 digits + ABA checksum |
| IBAN / SWIFT | IBAN mod-97 check |
| Passwords, API keys, tokens, private keys, 2FA codes | existing `outbound.py` secret patterns + entropy |
| Government IDs: passport, driver license, tax ID/EIN | regex + keyword context |
| Medical record numbers, insurance/member IDs | keyword context |
| Biometrics, health diagnoses tied to a person | local LLM pass |

## Tier 2: reversible placeholders (Claude only, never FreeLLMAPI)
Direct identifiers.
| Entity | Placeholder |
|---|---|
| Full name, first+last, signature names | `[PERSON_n]` |
| Phone number | `[PHONE_n]` |
| Email address | `[EMAIL_n]` |
| Street address, city+ZIP combined, geo coordinates | `[ADDRESS_n]` |
| Date of birth | `[DOB_n]` |
| Account nicknames / last-4 with institution | `[ACCOUNT_n]` |
| Employer, school, doctor/lawyer names | `[ORG_n]` |
| Usernames, customer/member numbers, device IDs, IP addresses | `[ID_n]` |
| Vehicle VIN / license plate | `[ID_n]` |
| URLs with tokens or personal paths | `[URL_n]` |

## Tier 3: financial transaction data (placeholders; amounts bucketed if analysis allows)
Treated as PII because they describe one person's activity.
| Entity | Handling |
|---|---|
| Transaction amounts, balances, income, salary, tax figures | `[AMOUNT_n]`; for calculations keep the math local and send only ratios or rounded buckets |
| Transaction dates tied to an account | shift to relative (`day +3`) or month only |
| Merchant / payee names on a statement | `[MERCHANT_n]` unless the merchant is the public subject of the question |
| Transaction descriptions, memo lines, check numbers | `[TXN_n]` |
| Loan, mortgage, credit scores, debts | `[AMOUNT_n]` / `[SCORE_n]` |
| Statement files and CSV/XLSX rows | whole rows never sent; summarize locally first |

## Tier 4: stricter rule for FreeLLMAPI and web search
No placeholders carrying structure. Send only generic text that was rewritten by the local model, e.g. "current 5-year CD rates", never "my balance of [AMOUNT_3]".
Web search queries: no tier 1-3 entity, no quasi-identifiers (rare job + city + age band).

## Quasi-identifiers (watch for re-identification)
Combinations such as ZIP + birth date + gender, or a rare employer + city. If two or more appear together, treat as tier 2. Implemented flags: zip+date, zip+gender, place+employer, dob+place, title+employer, medical+place, city+zip, name+financial. A flag makes a web query stop and makes places mask.

## Machine-readable policy
`src/privhybrid/pii_policy.json` lists each entity with its detection method, tier, masking, whether the masked form may go to a cloud service, and whether doubt blocks. `tests/security/test_pii_policy.py` checks every row against the detector and against this document, so a Tier 1 row here cannot quietly become a lower tier in code. Diagnoses and medication given as "diagnosed with ...", "diagnosis: ...", "medication: ..." or "prescribed ..." are Tier 1 and stop the request.

## Placeholder rules
- Stable within a session: same value -> same placeholder; different values never share one.
- Placeholders carry type and index only, never part of the value (no `[SSN_ends_1234]`).
- Map held in memory; written to disk only encrypted and only if resume is needed; never logged.
- Unmask locally. If the model returns an unknown or missing placeholder, flag it, do not guess.
- Case, spacing and format variants (`555.123.4567`, `(555) 123-4567`, `Jon Smith`/`SMITH, JON`) must hit the same placeholder.

## Detection stack
1. Regex + checksum validators (SSN, Luhn, ABA, IBAN, phone, email, dates).
2. Presidio recognizers with custom finance recognizers.
3. User dictionary: your own names, family, employer, accounts, merchants (editable file, local only).
4. Local LLM second pass on the redacted text: "list anything personal that remains". Any hit blocks and asks.

## Fail-closed behavior
- Tier 1 found: stop, ask. Never auto-send.
- Detector error, or more than 20% of text masked (existing `MAX_MASKED_RATIO`): stop, ask.
- Unsure: treat as sensitive.

## Test corpus (fake data only)
Include every row above plus format variants, names inside URLs and filenames, PII split across lines, PDFs/CSV rows, and canary strings. Pass bar: 100% of tier 1-2 planted values masked and restored; zero canaries in logs or captured outbound traffic.
