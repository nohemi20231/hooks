#!/bin/zsh
# Claude Code Stop hook: chime when the agent finishes a reply.
# If you've been away from the keyboard for 60s+, also speak the task title.
# macOS only (afplay, ioreg, say). Always exits 0 so it never blocks Claude.

SOUND="${AGENT_SOUND:-/System/Library/Sounds/Glass.aiff}"
IDLE_SECONDS="${AGENT_IDLE_SECONDS:-60}"

# Claude Code passes hook input as JSON on stdin (includes transcript_path).
input=$(cat)

/usr/bin/afplay "$SOUND" 2>/dev/null

# HIDIdleTime is in nanoseconds.
idle_ns=$(/usr/sbin/ioreg -c IOHIDSystem | /usr/bin/awk '/HIDIdleTime/ { print $NF; exit }')
(( ${idle_ns:-0} < IDLE_SECONDS * 1000000000 )) && exit 0

title=""
if command -v jq >/dev/null 2>&1; then
  transcript=$(print -r -- "$input" | jq -r '.transcript_path // empty')
  transcript="${transcript/#\~/$HOME}"
  if [[ -f "$transcript" ]]; then
    # Prefer Claude Code's session summary; fall back to the first prompt.
    title=$(jq -r 'select(.type=="summary") | .summary' "$transcript" 2>/dev/null | tail -1)
    if [[ -z "$title" ]]; then
      title=$(jq -r 'select(.type=="user" and (.message.content|type)=="string") | .message.content' \
        "$transcript" 2>/dev/null | head -1)
    fi
  fi
fi

# Keep it short enough to say out loud.
title=$(print -r -- "$title" | tr '\n' ' ' | cut -c1-80)

/usr/bin/say "${title:+Finished: $title}${title:-Agent finished}"
exit 0
