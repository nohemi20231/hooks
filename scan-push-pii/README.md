# scan-push-pii

A Claude Code `PreToolUse` hook that runs before every `git push` Claude issues.
It reads what the push would send and decides:

| Found | Tier | What happens |
|---|---|---|
| Secret (API key, private key, credential URL, bearer token, secret assignment) anywhere in the pushed tree, in any outgoing commit, or in a commit message | BLOCK | Push denied. No threshold, no bypass, no allowlist. Claude is told to move the value out and rewrite the commits. |
| Personal data (email, phone, SSN, card number, public IP) on a line the push adds, confidence ≥ 0.80 | AUTO | Push denied. Claude redacts without asking. |
| Personal data, confidence < 0.80 | ASK | Push denied. Claude asks you per item: redact, or keep (its fingerprint goes to the allowlist). |
| Protected file: transcript, conversation export, journal, diary, memory, personal notes (by path, or by content for `.json` / `.jsonl`) | BLOCK | Like a secret. First-person prose inside such a file blocks too. |
| Your own name or handle (patterns from the private `pii-own-names` file, 0.90 by default) | AUTO | A copyright line or a LICENSE / NOTICE / AUTHORS file drops it to ASK. |
| First-person prose (the writer talking about themself) on an added line of a `.md` / `.txt` / `.json` / `.yaml` file, 0.65 | ASK | Code, comments and fragments under five words are not prose. |

Nothing raw leaves the scan: values are masked to at most 2 + 2 characters, paths are masked
too, the log holds a hash of the command, and a crash denies the push with a readable reason
(fail closed).

## Install

```bash
ln -sf "$PWD/scan-push-pii/scan-push-pii.py" ~/.claude/hooks/scan-push-pii.py
```

The entry script finds its `pushscan/` package through the symlink. Merge
`claude-code.settings.json` into `~/.claude/settings.json` (keep `onFailure: block`), then
open `/hooks` in Claude Code once.

## Local state (never in the repo)

| File | Purpose |
|---|---|
| `~/.claude/hooks/.pii-salt` | random salt for fingerprints, mode 0600, made on first run |
| `~/.claude/hooks/pii-allowlist` | one fingerprint per line: ASK-tier personal data you chose to keep |
| `~/.claude/hooks/scan-push.log` | one masked line per decision |
| `~/.claude/hooks/pii-own-names` | your names: one regex per line, optional confidence (`vellanquist 0.70`); `#` comments. Missing file: names are not scanned. A bad line denies every push until fixed. |

`PUSHSCAN_STATE_DIR` moves all three (the tests point it at a temp folder).

## Layout

```
scan-push-pii.py        entry: stdin JSON → decision JSON
pushscan/command.py     static shell parse → every push in the command, with its cwd
pushscan/gitio.py       every git call; which refs a push sends; tree and diff reading
pushscan/detectors.py   one Detector + one scorer per kind
pushscan/scan.py        tree, outgoing commits, added lines → Findings
pushscan/policy.py      threshold, tier → action, state files, the text Claude receives
pushscan/findings.py    Hit, Finding, mask(), fingerprint()
tests/                  python3 -m unittest discover -s tests
```

## Limits

The command is parsed statically: shell variables other than `$HOME`, `$PWD` and `~` are not
expanded, and a push behind an unexpanded variable is a push candidate that git config decides.
`git stash push`, `echo "git push"` and commit messages are not pushes. A heredoc body counts
as commands only when it feeds a shell (`bash <<EOF`); a heredoc written to a file is data.

## Test

```bash
cd scan-push-pii && python3 -m unittest discover -s tests
```

`tests/test_repo_scan.py` runs the detectors over every file of this repository, so no
fixture may hold a secret-shaped or personal-shaped value in one piece (`tests/fixtures.py`
assembles them at runtime).
