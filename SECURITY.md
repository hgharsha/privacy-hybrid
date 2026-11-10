# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue.

- Use GitHub's **Report a vulnerability** button on the repository's Security tab (private vulnerability reporting).
- Include what you found, the steps to reproduce it, and the version or commit. Use synthetic data only; do not send real personal or financial documents.
- You can expect an acknowledgement within a few days. This is a small project run by one maintainer, so fixes are best effort and have no guaranteed timeline.
- Please give a reasonable time to fix before you publish details.

## Supported versions

Only the latest commit on `main` is supported.

## Threat model (summary)

The full guide is [docs/SECURITY.md](docs/SECURITY.md). In short:

- **Local by default.** Documents and questions are answered by a model on the same computer (Ollama). Nothing is sent anywhere unless the account has the permission and the user picks a cloud or web route.
- **The boundary.** Anything that leaves the computer goes through one code path (`egress.py`). Cloud text is masked first, checked again by the detector and a local model, and shown to the user for approval before it is sent. Personal identifiers of the strictest kind (such as government ids and card numbers) are never sent. Financial documents are reduced to a local summary of totals, and always need the user's approval.
- **Extreme privacy** is an application setting: the app does not use the web or the cloud and does not use a model on another computer. It is **not** a firewall.
- **Accounts and keys.** Each account's files are encrypted with a key derived from the password (scrypt, AES-GCM). There is no password recovery. The scheduler key is held in the macOS Keychain, never in a file. Files are readable by the owner only.
- **Isolation.** Accounts cannot read each other's data. A single administrator manages invitations, permissions and limits.
- **Optional OS-level lockdown.** `scripts/lockdown.sh` can block the app's user from the network at the operating-system level (macOS `pf`). It is optional, run by whoever installs the app, and not applied by default.

## Known limits

- The detector and the local checker are pattern- and model-based and can miss things. Look-alike letters from other alphabets are not caught.
- The in-app guard is Python-level. Without the OS lockdown, other processes on the computer are not restricted by it.
- A model on another computer on your network is plain HTTP unless you tunnel or use HTTPS.
- Scanned images without a text layer are not supported.
- File locking uses `flock` on macOS and Linux and a byte-range lock (`msvcrt`) on Windows. Owner-only access uses file modes on macOS and Linux and `icacls` on Windows.

Nothing here is a claim that the app is fully secure or that data cannot leak. The controls reduce risk; they do not remove it.

## Continuous security controls

- **Tests** on every push and pull request, including a separate security test run with the strict configuration (`.github/workflows/test.yml`).
- **Secret scanning** of the full git history with Gitleaks (`.github/workflows/security-scan.yml`).
- **Static analysis** with CodeQL (Python and JavaScript) and Bandit.
- **Dependency advisories** with `pip-audit`, and Dependabot updates for Python packages and GitHub Actions (`.github/dependabot.yml`).
- Weekly scheduled scans.
- Run the same checks locally before pushing: `scripts/verify-security.sh`.
