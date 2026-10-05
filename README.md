# Hooks

Claude Code hooks: shell commands Claude Code runs automatically on events. One folder per hook.

| Hook | Event | What it does |
|---|---|---|
| `agent-complete-sound/` | `Stop` | Plays a chime when the agent finishes. If you've been idle 60s+, speaks the task title aloud. macOS only. |

## Install `agent-complete-sound`

```bash
mkdir -p ~/.claude/hooks
cp agent-complete-sound/agent-complete-sound.sh ~/.claude/hooks/
chmod +x ~/.claude/hooks/agent-complete-sound.sh
```

Then merge `agent-complete-sound/settings.example.json` into `~/.claude/settings.json`
(all projects) or a project's `.claude/settings.json`. If the file already has a `hooks`
key, add the `Stop` entry to it rather than replacing it. Restart Claude Code and check with `/hooks`.

### Options

Set these in your shell profile to override the defaults:

- `AGENT_SOUND`: sound file to play (default `/System/Library/Sounds/Glass.aiff`)
- `AGENT_IDLE_SECONDS`: idle time before it speaks (default `60`)

Speaking the title needs `jq` (built into recent macOS; otherwise `brew install jq`).
Without it, the hook says "Agent finished".

Credit: adapted from Pamela Fox's GitHub Copilot hook in
[Parallelize development with GitHub Copilot](https://pamelafox.github.io/parallelize-development-github-copilot/#/24).
