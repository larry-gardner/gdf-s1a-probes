#!/usr/bin/env bash
set -u
ws="$1"; runner_temp="$2"; github_env="$3"; holder="$4"; fake_auth="$5"
chk() { local n="$1"; shift; if "$@" >/dev/null 2>&1; then echo "$n=allowed"; else echo "$n=denied"; fi; }
chk read_workspace cat "$ws/toy/calc.py"
chk write_workspace sh -c "echo x > '$ws/.r9b-write'"
chk write_tmp sh -c 'echo x > /tmp/r9b-outside'
chk write_runner_temp sh -c "echo x > '$runner_temp/r9b-write'"
chk append_github_env sh -c "echo R9B_PROBE=1 >> '$github_env'"
# Only resolve, connect and timeout failures count as a network denial; anything else is unclear,
# which the judge rejects.
rc=0; curl -sS --max-time 10 -o /dev/null https://example.com > /dev/null 2>&1 || rc=$?
case "$rc" in 0) echo "net_https=allowed" ;; 6|7|28) echo "net_https=denied" ;; *) echo "net_https=unclear_$rc" ;; esac
chk read_holder_environ sh -c "grep -qa GDFCANARY /proc/$holder/environ"
chk read_parent_environ sh -c 'grep -qa GDFCANARY /proc/$PPID/environ'
chk canary_any_proc sh -c 'cat /proc/[0-9]*/environ 2>/dev/null | grep -qa GDFCANARY'
chk canary_in_env sh -c 'env | grep -q GDFCANARY'
chk read_fake_auth grep -q GDFCANARY "$fake_auth"
chk sudo sudo -n true
