# Scheduled jobs: design (not built)

Status: built (src/privhybrid/schedule.py, sealed.py, keystore.py), tested with fake data. Date: 2026-10-31. Off unless `PRIVHYBRID_SCHEDULER=1`.

## Goal
Saved questions that run daily or weekly while the user is signed out. Results appear as "scheduled" chats at next sign-in.

## Decisions
- Two modes per job, chosen by the user: `web` (no files at all, enforced by an explicit pipeline flag) and `local` (one folder snapshot). No hybrid, no automatic switch.
- Claude route never allowed. Tier-1 data in input or output fails the run ("failed: sensitive data"); nothing is sent or stored.
- One-time per-account opt-in "Allow scheduled jobs while I'm signed out", off by default, plus a global server switch, off by default.
- Create, edit and run-now only while signed in.
- Limits: 20 jobs per user, minimum interval 1 hour, question 8000 characters, run timeout `UIORCH_LLM_TIMEOUT`, one scheduled job at a time, interactive questions win.
- Missed runs: run once at next start or sign-in with a "missed run" note, no backlog.
- Simple schedule (daily or weekly at a time), not cron.

## Construction
1. At opt-in: scheduler key S (32 random bytes) in the macOS Keychain; X25519 keypair, private key encrypted under the data key K, public key stored plain. K is never written or wrapped.
2. Job definitions encrypted under S so the scheduler can read them signed out. Question text is therefore protected by the Keychain, not the password.
3. Local jobs read a snapshot of the chosen folder, encrypted under S, never the main store. Refreshed at job creation, at each sign-in and on any library change. Deleting a file purges it from the snapshot at once. UI shows its date and a "refresh now" button. Renaming the folder re-snapshots.
4. Results sealed to the public key (ephemeral X25519, HKDF-SHA256 with a versioned info string, AES-GCM, random 12-byte nonce per item) into an inbox file (atomic write). Each item has a unique ID and a sequence number; duplicates are rejected at sign-in. No expiry, so an absence does not lose results.
5. HMAC (key derived from S, separate HKDF info) over each item. Items that fail show as "unverified".
6. Lifecycle: password change re-encrypts the private key only; delete account or opt-out removes the Keychain items, snapshot, definitions and inbox.
7. All new files mode 0600. Audit log keeps counts, route and timing only.

## Honest limits
- Malware running as the same user can read S, every scheduled question, every snapshot, and forge inbox items. The MAC only stops an attacker who can write the inbox but cannot read the Keychain. A MAC from K is impossible: the scheduler never has K.
- The login keychain file sits on disk and in Time Machine, protected by the Mac login password. With opt-in on, FileVault and a strong login password are required. Say so in the opt-in warning.
- Python cannot reliably wipe S from memory (bytearray, best effort only).
- Jobs fail softly ("Keychain unavailable") if the Mac was not unlocked since boot.

## Keychain spike (2026-10-31, this Mac, Python 3.9 + `keyring` macOS backend)
- The creating Python read its own item with no prompt.
- A different program (`security` CLI) reading it raised an "allow access" dialog, which blocks an unattended process. Access is tied to the program that created the item.
- A rebuilt venv (a different venv over the same Python binary) read it with no prompt.
- A launchd LaunchAgent (user session, no terminal) read it with no prompt.
- Not tested: a Python upgrade that changes the binary path (expect a prompt; the plan is to re-create the item when the interpreter changes and fail softly until then), a locked screen, a Mac that has not been unlocked since boot, and a LaunchDaemon with no user session (expected to fail: the login keychain is not available). Run the scheduler as a LaunchAgent.
