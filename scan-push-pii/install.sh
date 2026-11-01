#!/bin/sh
# Install scan-push-pii: the Claude Code hook (symlink) and the terminal pre-push hook (core.hooksPath).
# Safe to run again. Exits 1 without touching git config if core.hooksPath already points elsewhere.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd -P)
HOOKS_DIR="$HOME/.claude/hooks"

mkdir -p "$HOOKS_DIR"
ln -sfn "$HERE/scan-push-pii.py" "$HOOKS_DIR/scan-push-pii.py"
echo "Linked $HOOKS_DIR/scan-push-pii.py -> $HERE/scan-push-pii.py"

existing=$(git config --global --get core.hooksPath || true)
if [ -n "$existing" ]; then
  resolved=$(cd "$existing" 2>/dev/null && pwd -P || echo "$existing")
  if [ "$resolved" != "$HERE/git-hooks" ]; then
    echo "git core.hooksPath is already set to $existing and was left alone." >&2
    echo "Add $HERE/git-hooks/pre-push to that folder yourself, or unset core.hooksPath and run this again." >&2
    exit 1
  fi
fi
git config --global core.hooksPath "$HERE/git-hooks"
echo "Set git core.hooksPath to $HERE/git-hooks (pre-push runs on every terminal push)"

echo "Next: merge $HERE/claude-code.settings.json into $HOME/.claude/settings.json, then open /hooks once in Claude Code."
echo "Your own names go in $HOOKS_DIR/pii-own-names (one regex per line, optional confidence); keep that file private."
