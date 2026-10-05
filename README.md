# Hooks

Agent hooks: shell commands an AI coding agent runs automatically on events.
One folder per hook. Each hook works with Claude Code and GitHub Copilot where possible.

| Hook | Event | What it does |
|---|---|---|
| `agent-complete-sound/` | Stop / agentStop | Chimes when the agent finishes. If you've been idle 60s+, speaks which agent finished and on what. macOS only. |

## `agent-complete-sound`

One script for every agent. It reads the JSON the agent sends on stdin to work out
who called it, then says, for example:

- "Claude finished: Add rate limiting to the orders service"
- "Copilot finished: therapy" (Copilot CLI sends no transcript, so it uses the project folder)
- "Copilot hit an error: orders-api"

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

If a settings file already has a `hooks` key, add the entry to it rather than replacing it.
Restart the agent afterwards (`/hooks` in Claude Code lists what's loaded).

**Heads-up:** VS Code Copilot also reads Claude Code's `~/.claude/settings.json`.
If you register the hook in both places, VS Code may chime twice. Register it in one.

### Options

Set these in your shell profile to override the defaults:

| Variable | Default | Purpose |
|---|---|---|
| `AGENT_SOUND` | `/System/Library/Sounds/Glass.aiff` | Sound to play |
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

Credit: adapted from Pamela Fox's Copilot hook in
[Parallelize development with GitHub Copilot](https://pamelafox.github.io/parallelize-development-github-copilot/#/24).
