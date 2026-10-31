"""Judge R9b: every check must succeed outside the sandbox, and be denied inside it.

Usage: python3 -I r9b-judge.py OUTSIDE INSIDE. Exits 0 on pass, 1 on fail.
"""
import sys

CHECKS = ("read_workspace", "write_workspace", "write_tmp", "write_runner_temp", "append_github_env",
          "net_https", "read_holder_environ", "read_parent_environ", "canary_any_proc", "canary_in_env",
          "read_fake_auth", "sudo")
# Outside, sudo has already been dropped (R13), so it is the one expected denial.
OUTSIDE = {name: ("denied" if name == "sudo" else "allowed") for name in CHECKS}
# Inside, only the workspace read is allowed. read_fake_auth is recorded, not judged.
INSIDE = {name: ("allowed" if name == "read_workspace" else "denied") for name in CHECKS}
RECORDED_ONLY = {"read_fake_auth"}


def parse(text):
    seen = {}
    for line in text.splitlines():
        name, sep, value = line.strip().partition("=")
        if not sep or name not in CHECKS or value not in ("allowed", "denied") or name in seen:
            raise ValueError(f"unexpected line: {line!r}")
        seen[name] = value
    if set(seen) != set(CHECKS):
        raise ValueError(f"missing checks: {sorted(set(CHECKS) - set(seen))}")
    return seen


def judge(outside_text, inside_text):
    """Return (passed, problems, recorded)."""
    problems = []
    try:
        outside, inside = parse(outside_text), parse(inside_text)
    except ValueError as exc:
        return False, [str(exc)], {}
    for name in CHECKS:
        if outside[name] != OUTSIDE[name]:
            problems.append(f"outside {name}={outside[name]}, expected {OUTSIDE[name]}")
        if name not in RECORDED_ONLY and inside[name] != INSIDE[name]:
            problems.append(f"inside {name}={inside[name]}, expected {INSIDE[name]}")
    recorded = {name: inside[name] for name in RECORDED_ONLY}
    return not problems, problems, recorded


def main(argv):
    if len(argv) != 3:
        print("usage: r9b-judge.py OUTSIDE INSIDE", file=sys.stderr)
        return 2
    with open(argv[1]) as f_out, open(argv[2]) as f_in:
        passed, problems, recorded = judge(f_out.read(), f_in.read())
    for name, value in recorded.items():
        print(f"r9b_recorded {name}={value}")
    for problem in problems:
        print(f"::error::r9b {problem}")
    print("r9b=pass" if passed else "r9b=fail")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
