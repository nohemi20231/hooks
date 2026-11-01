"""Find every `git push` (and its equivalents) inside a Bash command string.

The hook receives the raw shell text Claude is about to run. This module answers, for each
push in it: which directory does it run in, and with which arguments.

It is a static, best-effort reading of shell text, not a shell. The rule is to err towards
finding a push: unknown programs followed by the word `push`, `xargs git`, aliases given on
the command line and heredoc bodies fed to a shell are all treated as pushes. A heredoc written
to a file is data. Variables other than `$HOME`, `$PWD` and the ones set in the same command
are not expanded; `$(...)` is left alone.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field

PUSH_SUBCOMMANDS = {"push", "send-pack"}
# git subcommands that are definitely not a push on their own (an alias could still be one;
# that is resolved later against the repo's config)
KNOWN_NON_PUSH = {
    "add", "am", "apply", "archive", "bisect", "blame", "branch", "bundle", "cat-file", "check-ignore",
    "checkout", "cherry", "cherry-pick", "citool", "clean", "clone", "commit", "config", "count-objects",
    "credential", "daemon", "describe", "diff", "difftool", "fetch", "filter-branch", "filter-repo",
    "flow", "for-each-ref", "format-patch", "fsck", "gc", "grep", "gui", "help", "init", "lfs", "log",
    "ls-files", "ls-tree", "maintenance", "merge", "mergetool", "mv", "name-rev", "notes", "pack-refs",
    "prune", "pull", "range-diff", "rebase", "reflog", "remote", "repack", "request-pull", "reset",
    "restore", "rev-list", "rev-parse", "revert", "rm", "send-email", "shortlog", "show", "show-ref",
    "sparse-checkout", "stash", "status", "submodule", "switch", "symbolic-ref", "tag", "update-index",
    "var", "version", "worktree",
}
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix"}
# programs that run the program named after them (plus their own options)
WRAPPERS = {"command", "exec", "nohup", "time", "nice", "ionice", "timeout", "sudo", "doas", "caffeinate",
            "builtin", "stdbuf", "unbuffer", "chronic", "env"}
WRAPPER_OPTS_WITH_VALUE = {"-n", "-c", "-u", "--unset", "-C", "--chdir", "-S", "--split-string", "-k", "-s"}
SHELL_KEYWORDS = {"{", "}", "!", "do", "done", "then", "else", "elif", "fi", "if", "while", "until", "esac"}
SEPARATORS = {"&&", "||", ";", ";;", "|", "|&", "&", "\n"}
REDIRECT = re.compile(r"^\d*[<>]+&?\d*$|^<<-?$|^<<<$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
INLINE_ALIAS = re.compile(r"alias\.([\w-]+)=(.+)")
HEREDOC = re.compile(r"(?<!<)<<-?(?!<)\s*(?:'([^']+)'|\"([^\"]+)\"|\\?(\w+))")


@dataclass
class Push:
    """One push found in the command."""
    cwd: str
    args: list[str] = field(default_factory=list)
    subcommand: str = "push"
    certain: bool = True                     # False: `subcommand` may be an alias; git config decides
    tool: str = "git"


@dataclass
class _Shell:
    """What the shell would know at the point a segment runs."""
    cwd: str
    previous_cwd: str
    env: dict[str, str] = field(default_factory=dict)


def find_pushes(command: str, cwd: str) -> list[Push]:
    """Return every push in `command`, in order, each with the directory it runs in."""
    try:
        tokens = _tokenize(command)
    except ValueError:
        # unbalanced quotes: the shell would refuse it too; nothing to scan
        return []
    shell = _Shell(cwd=cwd, previous_cwd=cwd)
    pushes: list[Push] = []
    subshell_stack: list[str] = []
    for segment in _segments(tokens):
        if segment == ["("]:
            subshell_stack.append(shell.cwd)
        elif segment == [")"]:
            if subshell_stack:
                shell.cwd = subshell_stack.pop()
        else:
            pushes.extend(_pushes_in_segment(segment, shell))
    return pushes


# ---------------------------------------------------------------- lexing

def _tokenize(command: str) -> list[str]:
    command = _backticks_as_subshells(_drop_data_heredocs(command))
    lexer = shlex.shlex(command, posix=True, punctuation_chars="();|&")
    lexer.whitespace = " \t\r"                   # newlines separate commands, so keep them as tokens
    lexer.whitespace_split = True
    lexer.commenters = ""                        # a `#` inside a word is not a comment; handled below
    tokens: list[str] = []
    for token in lexer:
        if "\n" in token:
            tokens.extend(_split_newlines(token))
        else:
            tokens.append(token)
    return tokens


def _drop_data_heredocs(command: str) -> str:
    """A heredoc body is commands only when the line feeds a shell (`bash <<EOF`, `ssh host sh <<EOF`).
    Written to a file or piped to any other program it is data, and a push named inside it is text."""
    kept: list[str] = []
    pending: list[tuple[str, bool]] = []          # (terminator, body is commands)
    for line in command.split("\n"):
        if pending:
            terminator, is_commands = pending[0]
            if line.strip() == terminator:
                pending.pop(0)
            if is_commands:
                kept.append(line)
            continue
        feeds_a_shell = any(os.path.basename(word) in SHELLS for word in line.split())
        for m in HEREDOC.finditer(line):
            pending.append((m.group(1) or m.group(2) or m.group(3), feeds_a_shell))
        kept.append(line)
    return "\n".join(kept)


def _backticks_as_subshells(command: str) -> str:
    """`...` runs like $(...): give it the same shape so the body is read as its own segment."""
    parts = command.split("`")
    for i in range(1, len(parts), 2):
        parts[i] = f" ( {parts[i]} ) "
    return "".join(parts)


def _split_newlines(token: str) -> list[str]:
    """A token that spans lines (heredoc body, unquoted newline) becomes words and newline markers."""
    out: list[str] = []
    for i, part in enumerate(token.split("\n")):
        if i:
            out.append("\n")
        out.extend(part.split())
    return out


def _segments(tokens: list[str]):
    """Split on shell separators; parentheses come out as their own one-token segments.
    A word starting with `#` begins a comment that lasts to the end of the line."""
    segment: list[str] = []
    in_comment = False
    for token in tokens:
        if token == "\n":
            in_comment = False
        if in_comment:
            continue
        if token.startswith("#"):
            in_comment = True
            continue
        if token in SEPARATORS:
            if segment:
                yield segment
            segment = []
        elif token in ("(", ")"):
            if segment:
                yield segment
            segment = []
            yield [token]
        elif REDIRECT.match(token):
            continue
        else:
            segment.append(token)
    if segment:
        yield segment


# ---------------------------------------------------------------- one segment

def _pushes_in_segment(segment: list[str], shell: _Shell) -> list[Push]:
    words = _strip_keywords(segment)
    env, words = _split_leading_assignments(words, shell)
    words = _strip_wrappers(words, shell)
    if not words:
        return []
    program = os.path.basename(words[0].lstrip("\\"))
    if program == "export":
        for word in words[1:]:
            if ASSIGNMENT.match(word):
                key, value = word.split("=", 1)
                shell.env[key] = value
        return []
    if program in ("cd", "pushd"):
        shell.previous_cwd, shell.cwd = shell.cwd, _change_directory(words[1:], shell)
        return []
    if program == "popd":
        shell.cwd, shell.previous_cwd = shell.previous_cwd, shell.cwd
        return []
    if program == "eval":
        return find_pushes(" ".join(words[1:]), shell.cwd)
    if program in SHELLS:
        script = _inline_script(words[1:])
        return find_pushes(script, shell.cwd) if script else []
    if program == "gh":
        push = _parse_gh(words[1:], shell.cwd)
        return [push] if push else []
    if program == "xargs":
        return _parse_xargs(words[1:], env, shell)
    if program == "git":
        return _parse_git_everywhere(words[1:], env, shell.cwd)
    if program.startswith("$") and "push" in words[1:]:
        # `$g push`: the program is a variable we cannot read; let git config decide later
        return [Push(cwd=shell.cwd, args=words[words.index("push") + 1:], subcommand="push", certain=False)]
    return []


def _strip_keywords(words: list[str]) -> list[str]:
    if words[:1] == ["for"] or "in" in words[:3] and words[:1] in (["case"], ["select"]):
        return []                                  # `for r in a b` / `case x in` hold no command
    i = 0
    while i < len(words) and words[i] in SHELL_KEYWORDS:
        i += 1
    while len(words) > i and words[-1] in ("}", "done", "fi", "esac"):
        words = words[:-1]
    return words[i:]


def _split_leading_assignments(words: list[str], shell: _Shell) -> tuple[dict[str, str], list[str]]:
    """`FOO=1 git push` -> ({FOO: 1}, [git, push]); the shell's exported variables come first."""
    env = dict(shell.env)
    i = 0
    while i < len(words) and ASSIGNMENT.match(words[i]):
        key, value = words[i].split("=", 1)
        env[key] = value
        i += 1
    if i == len(words):                            # a bare `g=git` segment sets variables for later
        shell.env.update(env)
    return env, words[i:]


def _strip_wrappers(words: list[str], shell: _Shell) -> list[str]:
    """Drop `nohup`, `timeout 30`, `env -u X`, `sudo -u user` ... and their options."""
    while words and os.path.basename(words[0]) in WRAPPERS:
        wrapper, rest = os.path.basename(words[0]), words[1:]
        i = 0
        while i < len(rest):
            word = rest[i]
            if word in ("-C", "--chdir") and wrapper == "env" and i + 1 < len(rest):
                shell.cwd = _expand(rest[i + 1], shell)
                i += 2
            elif word in WRAPPER_OPTS_WITH_VALUE:
                i += 2
            elif word.startswith("-"):
                i += 1
            elif wrapper in ("timeout", "nice", "ionice") and re.fullmatch(r"\d+[smhd]?", word):
                i += 1
            elif ASSIGNMENT.match(word) and wrapper == "env":
                key, value = word.split("=", 1)
                shell.env[key] = value
                i += 1
            else:
                break
        words = rest[i:]
    return words


def _inline_script(args: list[str]) -> str:
    """The script in `sh -c '...'`, `bash -lc '...'` and the like."""
    for i, arg in enumerate(args):
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            return args[i + 1] if i + 1 < len(args) else ""
    return ""


def _expand(path: str, shell: _Shell) -> str:
    """Expand ~, $VAR and ${VAR}; $PWD means the directory the command is in at that point.
    A `$(...)` we cannot run leaves the directory unchanged."""
    if "$(" in path:
        return shell.cwd
    known = {"HOME": os.path.expanduser("~"), "PWD": shell.cwd, **shell.env}

    def value_of(m: re.Match) -> str:
        name = m.group(1) or m.group(2)
        return known.get(name, os.environ.get(name, ""))

    path = re.sub(r"\$\{(\w+)\}|\$(\w+)", value_of, path)
    path = os.path.expanduser(path)
    return path if os.path.isabs(path) else os.path.normpath(os.path.join(shell.cwd, path))


def _change_directory(args: list[str], shell: _Shell) -> str:
    targets = [a for a in args if not a.startswith("-") or a == "-"]
    if not targets:
        return os.path.expanduser("~")
    if targets[0] == "-":
        return shell.previous_cwd
    return _expand(targets[0], shell)


# ---------------------------------------------------------------- git and friends

def _parse_git_everywhere(args: list[str], env: dict[str, str], cwd: str) -> list[Push]:
    """`git submodule foreach git push` holds a second git: parse every git in the words."""
    pushes: list[Push] = []
    push = _parse_git(args, env, cwd)
    if push:
        pushes.append(push)
    for i, word in enumerate(args):
        if os.path.basename(word) == "git":
            pushes.extend(_parse_git_everywhere(args[i + 1:], env, cwd))
            break
    return pushes


def _parse_git(args: list[str], env: dict[str, str], cwd: str) -> Push | None:
    git_dir = env.get("GIT_DIR")
    work_tree = env.get("GIT_WORK_TREE")
    shell = _Shell(cwd=cwd, previous_cwd=cwd, env=env)
    inline_aliases = _aliases_in(env.get("GIT_CONFIG_PARAMETERS", ""))
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in GIT_OPTS_WITH_VALUE:
            value = args[i + 1] if i + 1 < len(args) else ""
            i += 2
        elif arg.startswith("--") and "=" in arg and arg.split("=", 1)[0] in GIT_OPTS_WITH_VALUE:
            arg, value = arg.split("=", 1)
            i += 1
        elif arg.startswith("-"):
            i += 1
            continue
        else:
            break
        if arg == "-C":
            shell.cwd = _expand(value, shell)
        elif arg == "--git-dir":
            git_dir = value
        elif arg == "--work-tree":
            work_tree = value
        elif arg == "-c":
            inline_aliases.update(_aliases_in(value))
    if i >= len(args):
        return None
    subcommand, rest = args[i], args[i + 1:]
    if subcommand in inline_aliases:
        expansion = inline_aliases[subcommand].lstrip("!").split()
        if expansion and os.path.basename(expansion[0]) == "git":
            expansion = expansion[1:]
        if not expansion:
            return None
        subcommand, rest = expansion[0], expansion[1:] + rest
    if subcommand in KNOWN_NON_PUSH:
        return None
    if work_tree:
        shell.cwd = _expand(work_tree, shell)
    elif git_dir:
        git_dir = _expand(git_dir, shell)
        shell.cwd = os.path.dirname(git_dir) if os.path.basename(git_dir) == ".git" else git_dir
    return Push(cwd=shell.cwd, args=rest, subcommand=subcommand, certain=(subcommand in PUSH_SUBCOMMANDS))


def _aliases_in(text: str) -> dict[str, str]:
    return {m.group(1): m.group(2).strip("'\" ") for m in INLINE_ALIAS.finditer(text)}


def _parse_xargs(args: list[str], env: dict[str, str], shell: _Shell) -> list[Push]:
    """`... | xargs git`: the subcommand comes from stdin, which we cannot read; treat as a candidate."""
    words = _strip_wrappers([a for a in args if not a.startswith("-")], shell)
    if not words or os.path.basename(words[0]) != "git":
        return []
    push = _parse_git(words[1:], env, shell.cwd)
    if push:
        return [push]
    return [Push(cwd=shell.cwd, args=[], subcommand="?", certain=False)]


def _parse_gh(args: list[str], cwd: str) -> Push | None:
    words: list[str] = []
    i = 0
    while i < len(args):
        if args[i] in ("-R", "--repo") and i + 1 < len(args):
            i += 2
        elif args[i].startswith("-"):
            i += 1
        else:
            words.append(args[i])
            i += 1
    if words[:2] in (["repo", "sync"], ["pr", "create"]):
        return Push(cwd=cwd, args=[], subcommand=" ".join(words[:2]), certain=True, tool="gh")
    return None
