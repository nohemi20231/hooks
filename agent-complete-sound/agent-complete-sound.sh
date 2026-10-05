#!/bin/bash
# Agent-complete sound hook for Claude Code, GitHub Copilot in VS Code, and Copilot CLI.
#
# Chimes when the agent finishes. If you've been away from the keyboard for
# IDLE_SECONDS or more, it also speaks which agent finished and on what.
# The script detects which tool called it from the JSON it receives on stdin.
#
# macOS only (afplay, ioreg, say). Always exits 0 so it never blocks the agent.
# Works with macOS's built-in bash 3.2.

SOUND="${AGENT_SOUND:-/System/Library/Sounds/Glass.aiff}"
IDLE_SECONDS="${AGENT_IDLE_SECONDS:-60}"
DRY_RUN="${AGENT_SOUND_DRY_RUN:-0}"   # 1 = print instead of playing/speaking (for testing)

input=$(cat)

have_jq() { command -v jq >/dev/null 2>&1; }

# Read the first non-empty value among several JSON paths (handles
# snake_case from Claude Code / VS Code and camelCase from Copilot CLI).
field() {
  have_jq || return 0
  printf '%s' "$input" | jq -r "[$1] | map(select(. != null and . != \"\")) | first // empty" 2>/dev/null
}

play() { [ "$DRY_RUN" = 1 ] && echo "PLAY $SOUND" || /usr/bin/afplay "$SOUND" 2>/dev/null; }
speak() { [ "$DRY_RUN" = 1 ] && echo "SAY $1" || /usr/bin/say "$1"; }

idle_seconds() {
  [ "$DRY_RUN" = 1 ] && { echo "${AGENT_FAKE_IDLE:-999}"; return; }
  local ns
  ns=$(/usr/sbin/ioreg -c IOHIDSystem | /usr/bin/awk '/HIDIdleTime/ { print $NF; exit }')
  echo $(( ${ns:-0} / 1000000000 ))
}

# --- Which agent called us? -------------------------------------------------
transcript=$(field '.transcript_path, .transcriptPath')
transcript="${transcript/#\~/$HOME}"
event=$(field '.hook_event_name, .hookEventName')
reason=$(field '.reason, .stopReason')
cwd=$(field '.cwd')

if [ -n "$AGENT_NAME" ]; then
  agent="$AGENT_NAME"
elif case "$transcript" in */.claude/*) true;; *) false;; esac; then
  agent="Claude"
elif [ -n "$CLAUDE_PROJECT_DIR" ] && [ "$event" != "agentStop" ] && [ "$event" != "sessionEnd" ]; then
  agent="Claude"   # Claude Code sets CLAUDE_PROJECT_DIR for hooks
elif [ "$event" = "agentStop" ] || [ "$event" = "sessionEnd" ] || [ -n "$(field '.sessionId')" ] || case "$transcript" in *[Cc]opilot*|*[Cc]ode*) true;; *) false;; esac; then
  agent="Copilot"
else
  agent="Agent"
fi

# --- Chime, then speak only if you've stepped away --------------------------
play
[ "$(idle_seconds)" -lt "$IDLE_SECONDS" ] && exit 0

# --- What was it working on? ------------------------------------------------
title=""
if have_jq && [ -f "$transcript" ]; then
  # Claude Code: session summary, if one has been written.
  title=$(jq -r 'select(.type=="summary") | .summary // empty' "$transcript" 2>/dev/null | tail -1)
  # Otherwise the first prompt. Tries the common transcript shapes
  # (Claude Code JSONL and Copilot-style messages).
  if [ -z "$title" ]; then
    title=$(jq -r '
      select((.type // .role // .message.role) == "user")
      | (.message.content // .content // .text // .prompt)
      | if type == "string" then . elif type == "array" then (map(.text? // empty) | join(" ")) else empty end
      | select(length > 0)' "$transcript" 2>/dev/null | head -1)
  fi
fi
# Fall back to the project folder name.
[ -z "$title" ] && [ -n "$cwd" ] && title="${cwd##*/}"

title=$(printf '%s' "$title" | tr '\n\t' '  ' | cut -c1-80)

case "$reason" in
  error)   verb="hit an error" ;;
  timeout) verb="timed out" ;;
  abort)   verb="was stopped" ;;
  *)       verb="finished" ;;
esac

if [ -n "$title" ]; then
  speak "$agent $verb: $title"
else
  speak "$agent $verb"
fi
exit 0
