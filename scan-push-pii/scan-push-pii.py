#!/usr/bin/env python3
"""Claude Code PreToolUse hook (matcher: Bash). Runs before every `git push` Claude issues.

Secrets and protected files anywhere in what would be pushed block the push, no bypass.
Personal data on added lines is confidence-scored: >= 0.80 Claude redacts, < 0.80 Claude asks.
See pushscan/policy.py for the rules and pushscan/detectors.py for what is detected.

Run the tests with:  cd ~/.claude/hooks && python3 -m unittest discover -s tests
"""
import os
import sys

# `python3 -I` keeps the script directory off sys.path on purpose; add only this directory back.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))   # realpath: ~/.claude/hooks holds a symlink

from pushscan.hook import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
