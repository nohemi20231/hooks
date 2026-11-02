# Hooks

Agent hooks: shell commands an AI coding agent runs automatically on events.
One folder per hook. Each hook works with Claude Code and GitHub Copilot where possible.

| Hook | Event | What it does |
|---|---|---|
| `agent-complete-sound/` | Stop / agentStop, Notification | Chimes when the agent finishes or is waiting on you (Claude Code). If you've been idle 60s+, speaks which agent and on what. macOS only. |
| `scan-push-pii/` | PreToolUse (Bash) in Claude Code; git `pre-push` in a terminal | Scans what a push would send. Secrets and protected files block with no bypass; personal data is confidence-scored (≥ 0.80 Claude redacts, below it asks you). Python 3, no dependencies. |

## `agent-complete-sound`

One script for every agent. It reads the JSON the agent sends on stdin to work out
who called it, then says, for example:

- "Claude finished: Add rate limiting to the orders service"
- "Copilot finished: therapy" (Copilot CLI sends no transcript, so it uses the project folder)
- "Copilot hit an error: orders-api"
- "Claude needs you: Add rate limiting to the orders service" (Claude Code is waiting on a
  permission prompt or your input, mid-task)

### Install the script (once)

```bash
mkdir -p ~/.claude/hooks ~/.copilot/hooks
cp agent-complete-sound/agent-complete-sound.sh ~/.claude/hooks/
cp agent-complete-sound/agent-complete-sound.sh ~/.copilot/hooks/
chmod +x ~/.claude/hooks/agent-complete-sound.sh ~/.copilot/hooks/agent-complete-sound.sh
```

### Register it with each agent

| Agent | Config file | Merge in |
|---|---|---|
| Claude Code | `~/.claude/settings.json` | `claude-code.settings.json` |
| Copilot in VS Code | `~/.copilot/hooks/agent-complete-sound.json` | `copilot-vscode.hooks.json` |
| Copilot CLI | `~/.copilot/hooks/agent-complete-sound-cli.json` | `copilot-cli.hooks.json` |

If a settings file already has a `hooks` key, add the entries to it rather than replacing it.
For Claude Code, register both `Stop` (finished) and `Notification` (waiting on you).
Restart the agent afterwards (`/hooks` in Claude Code lists what's loaded).

**Heads-up:** VS Code Copilot also reads Claude Code's `~/.claude/settings.json`.
If you register the hook in both places, VS Code may chime twice. Register it in one.

### Options

Set these in your shell profile to override the defaults:

| Variable | Default | Purpose |
|---|---|---|
| `AGENT_SOUND` | `/System/Library/Sounds/Submarine.aiff` | Sound to play (shown as "Submerge" in System Settings) |
| `AGENT_IDLE_SECONDS` | `60` | Idle time before it speaks |
| `AGENT_NAME` | auto-detected | Force the spoken agent name |
| `AGENT_SOUND_DRY_RUN` | `0` | `1` prints instead of playing/speaking |

Speaking the task title needs `jq` (built into recent macOS; otherwise `brew install jq`).
Without it the hook still chimes and says "Agent finished".

### Test it

```bash
echo '{"sessionId":"x","cwd":"'"$PWD"'","reason":"complete"}' \
  | AGENT_SOUND_DRY_RUN=1 ./agent-complete-sound/agent-complete-sound.sh
```

Credit: adapted from Pamela Fox's [agent completion hook](https://gist.github.com/pamelafox/c9cb3e000fdf127741b121d7c5abbf02), shown in
[Parallelize development with GitHub Copilot](https://pamelafox.github.io/parallelize-development-github-copilot/#/24).

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

Copyright 2026 Nohemi Gonzalez Lopez. Licensed under the [Apache License, Version 2.0](LICENSE). Keep the [`NOTICE`](NOTICE) file when redistributing.
