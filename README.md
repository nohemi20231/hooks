# Hooks

Agent hooks: shell commands an AI coding agent runs automatically on events.
One folder per hook. Each hook works with Claude Code and GitHub Copilot where possible.

| Hook | Event | What it does |
|---|---|---|
| `scan-push-pii/` | PreToolUse (Bash) in Claude Code; git `pre-push` in a terminal | Scans what a push would send. Secrets and protected files block with no bypass; personal data is confidence-scored (≥ 0.80 Claude redacts, below it asks you). Python 3, no dependencies. |

## `scan-push-pii`

Before a push reaches GitHub, the whole pushed tree and every outgoing commit are scanned for
secrets (API keys, private keys, credential URLs, bearer tokens, secret assignments) and for
protected files (transcripts, journals, memory, personal notes); any hit blocks the push, no
threshold, no allowlist. Lines the push adds are scanned for personal data (emails, phones, SSNs,
cards, your own names from a private file): at or above 0.80 confidence
Claude redacts, below it Claude asks you per item. Nothing raw is printed or logged.

```bash
sh scan-push-pii/install.sh
```

Details, the detector table and the private files it reads: [`scan-push-pii/README.md`](scan-push-pii/README.md).

## License

[MIT](LICENSE).
