"""How the hook finds a push inside a Bash command string, and where that push runs."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pushscan.command import find_pushes  # noqa: E402

CWD = "/repo"


def one(command, cwd=CWD):
    pushes = find_pushes(command, cwd)
    assert len(pushes) == 1, pushes
    return pushes[0]


class PlainPush(unittest.TestCase):
    def test_git_push_is_found(self):
        push = one("git push")
        self.assertEqual(push.cwd, "/repo")
        self.assertEqual(push.args, [])

    def test_push_args_are_kept(self):
        push = one("git push -u origin main")
        self.assertEqual(push.args, ["-u", "origin", "main"])

    def test_double_spaces_and_tabs(self):
        self.assertEqual(one("git \t push   origin").args, ["origin"])

    def test_absolute_git_path(self):
        self.assertEqual(one("/usr/bin/git push").args, [])

    def test_quoted_program_name(self):
        self.assertEqual(one('"git" push').args, [])

    def test_force_push(self):
        self.assertEqual(one("git push --force origin main").args, ["--force", "origin", "main"])


class NotAPush(unittest.TestCase):
    def test_stash_push_is_not_a_push(self):
        self.assertEqual(find_pushes("git stash push", CWD), [])

    def test_commit_message_mentioning_push(self):
        self.assertEqual(find_pushes("git commit -m 'note: run git push later'", CWD), [])

    def test_echo_push(self):
        self.assertEqual(find_pushes("echo 'git push'", CWD), [])

    def test_unrelated_command(self):
        self.assertEqual(find_pushes("ls -la", CWD), [])

    def test_git_without_subcommand(self):
        self.assertEqual(find_pushes("git", CWD), [])


class GlobalOptions(unittest.TestCase):
    def test_dash_C_absolute(self):
        push = one("git -C /abs/path/r1 push")
        self.assertEqual(push.cwd, "/abs/path/r1")

    def test_dash_C_relative_to_cwd(self):
        self.assertEqual(one("git -C r1 push").cwd, "/repo/r1")

    def test_dash_C_dot(self):
        self.assertEqual(one("git -C . push").cwd, "/repo")

    def test_work_tree_option(self):
        push = one("git --git-dir=/x/.git --work-tree=/x push")
        self.assertEqual(push.cwd, "/x")

    def test_git_dir_without_work_tree_uses_its_parent(self):
        self.assertEqual(one("git --git-dir=/x/.git push").cwd, "/x")

    def test_dash_c_config_is_skipped(self):
        push = one("git -c core.quotePath=off push origin main")
        self.assertEqual(push.args, ["origin", "main"])

    def test_GIT_DIR_env_prefix(self):
        self.assertEqual(one("GIT_DIR=/x/.git git push").cwd, "/x")

    def test_env_command_prefix(self):
        self.assertEqual(one("env FOO=1 git push").cwd, "/repo")


class WorkingDirectoryChain(unittest.TestCase):
    def test_cd_then_push(self):
        self.assertEqual(one("cd r1 && git push").cwd, "/repo/r1")

    def test_two_cds(self):
        self.assertEqual(one("cd /a && cd b && git push", cwd="/").cwd, "/a/b")

    def test_cd_after_push_does_not_matter(self):
        self.assertEqual(one("git push && cd ..").cwd, "/repo")

    def test_semicolon_separator(self):
        self.assertEqual(one("cd r1; git push").cwd, "/repo/r1")

    def test_subshell(self):
        self.assertEqual(one("(cd r1 && git push)").cwd, "/repo/r1")

    def test_pushd(self):
        self.assertEqual(one("pushd r1 && git push").cwd, "/repo/r1")

    def test_cd_with_quotes_and_spaces(self):
        self.assertEqual(one('cd "/path/r1 copy" && git push').cwd, "/path/r1 copy")

    def test_cd_with_single_quotes(self):
        self.assertEqual(one("cd '/path/r1 copy' && git push").cwd, "/path/r1 copy")

    def test_cd_home_variable(self):
        home = os.path.expanduser("~")
        self.assertEqual(one('cd "$HOME/x" && git push').cwd, f"{home}/x")

    def test_cd_tilde(self):
        home = os.path.expanduser("~")
        self.assertEqual(one("cd ~/x && git push").cwd, f"{home}/x")

    def test_cd_dollar_pwd(self):
        self.assertEqual(one("cd $PWD/r1 && git push").cwd, "/repo/r1")

    def test_cd_with_no_argument_goes_home(self):
        self.assertEqual(one("cd && git push").cwd, os.path.expanduser("~"))

    def test_sh_dash_c(self):
        self.assertEqual(one("sh -c 'cd r1 && git push'").cwd, "/repo/r1")

    def test_bash_dash_c(self):
        self.assertEqual(one('bash -c "git push origin main"').args, ["origin", "main"])

    def test_pipe_separator(self):
        self.assertEqual(one("git push 2>&1 | tee log").args, [])


class SeveralPushes(unittest.TestCase):
    def test_two_pushes_in_one_command(self):
        pushes = find_pushes("git push origin a && cd ../other && git push", CWD)
        self.assertEqual([(p.cwd, p.args) for p in pushes], [("/repo", ["origin", "a"]), ("/other", [])])


class GhCli(unittest.TestCase):
    def test_gh_repo_sync_is_a_push(self):
        push = one("gh repo sync")
        self.assertEqual(push.cwd, "/repo")
        self.assertEqual(push.args, [])

    def test_gh_pr_create_is_a_push(self):
        self.assertEqual(one("gh pr create --fill").cwd, "/repo")

    def test_gh_pr_view_is_not(self):
        self.assertEqual(find_pushes("gh pr view", CWD), [])


class Aliases(unittest.TestCase):
    def test_unknown_subcommand_is_reported_as_candidate(self):
        """`git p` may be an alias for push; the hook asks git later. Here it is kept as a candidate."""
        push = one("git p origin main")
        self.assertEqual(push.subcommand, "p")
        self.assertEqual(push.args, ["origin", "main"])
        self.assertFalse(push.certain)

    def test_known_push_is_certain(self):
        self.assertTrue(one("git push").certain)

    def test_known_non_push_is_not_a_candidate(self):
        self.assertEqual(find_pushes("git status", CWD), [])


class MultiLineAndKeywords(unittest.TestCase):
    """Reviewer items 1, 2 and 4: everyday shapes Claude writes."""
    def test_push_on_the_second_line(self):
        self.assertEqual(one("echo start\ngit push").args, [])

    def test_cd_then_push_on_the_next_line(self):
        self.assertEqual(one("cd sub\ngit push").cwd, "/repo/sub")

    def test_heredoc_body_line(self):
        self.assertEqual(len(find_pushes("bash <<EOF\ngit push\nEOF", CWD)), 1)

    def test_brace_group(self):
        self.assertEqual(len(find_pushes("true && { git push; }", CWD)), 1)

    def test_for_loop(self):
        self.assertEqual(one("for r in origin; do git push $r; done").subcommand, "push")

    def test_if_then(self):
        self.assertEqual(len(find_pushes("if true; then git push; fi", CWD)), 1)

    def test_negated(self):
        self.assertEqual(len(find_pushes("! git push", CWD)), 1)

    def test_hash_inside_a_word_is_not_a_comment(self):
        self.assertEqual(len(find_pushes("echo done#1 && git push", CWD)), 1)

    def test_hash_at_word_start_is_a_comment_to_end_of_line(self):
        self.assertEqual(find_pushes("echo x # git push", CWD), [])
        self.assertEqual(len(find_pushes("echo x # note\ngit push", CWD)), 1)


class Wrappers(unittest.TestCase):
    """Reviewer item 3 and 5: programs that run another program."""
    def test_command_exec_nohup_time_nice(self):
        for w in ("command git push", "exec git push", "nohup git push", "time git push", "nice git push",
                  "nice -n 5 git push", "timeout 30 git push", "sudo git push", "caffeinate -i git push"):
            self.assertEqual(len(find_pushes(w, CWD)), 1, w)

    def test_eval_string(self):
        self.assertEqual(len(find_pushes('eval "git push origin main"', CWD)), 1)

    def test_backticks(self):
        self.assertEqual(len(find_pushes("echo `git push`", CWD)), 1)

    def test_xargs_git_is_a_candidate(self):
        push = one("echo push | xargs git")
        self.assertFalse(push.certain)

    def test_bash_lc_and_ec(self):
        self.assertEqual(len(find_pushes('bash -lc "git push"', CWD)), 1)
        self.assertEqual(len(find_pushes('bash -ec "git push"', CWD)), 1)

    def test_env_unset_then_git(self):
        self.assertEqual(len(find_pushes("env -u FOO git push", CWD)), 1)

    def test_env_chdir(self):
        self.assertEqual(one("env -C /other git push").cwd, "/other")

    def test_export_git_dir_persists_across_segments(self):
        self.assertEqual(one("export GIT_DIR=/r1/.git; git push").cwd, "/r1")

    def test_variable_program_with_push_word_is_a_candidate(self):
        push = one("g=git; $g push")
        self.assertFalse(push.certain)


class OtherPushShapes(unittest.TestCase):
    """Reviewer items 6 and 7: aliases given on the command line, send-pack, submodule foreach, gh flags."""
    def test_inline_alias_via_dash_c(self):
        push = one("git -c alias.x=push x")
        self.assertEqual(push.subcommand, "push")
        self.assertTrue(push.certain)

    def test_inline_alias_via_git_config_parameters(self):
        push = one("GIT_CONFIG_PARAMETERS=\"'alias.x=push'\" git x")
        self.assertTrue(push.certain)

    def test_send_pack_is_a_push(self):
        self.assertTrue(one("git send-pack origin main").certain)

    def test_submodule_foreach_git_push(self):
        self.assertEqual(len(find_pushes("git submodule foreach git push", CWD)), 1)

    def test_gh_repo_flag_before_subcommand(self):
        self.assertEqual(one("gh --repo x/y repo sync").tool, "gh")
