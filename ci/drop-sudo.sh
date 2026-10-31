#!/usr/bin/env bash
# Remove the runner user's routes to root before any agent starts (S1a R13).
# Modelled on the behaviour openai/codex-action documents for its drop-sudo strategy; this is an
# independent implementation. It runs as the runner user while sudo still works, and fails closed.
# The workflow's next step, a new process, verifies the result independently.
set -euo pipefail

# Test hooks only: the workflow never sets these, and the script runs before any agent exists.
etc="${S1A_ETC:-/etc}"
run="${S1A_RUN:-/run}"
socket_owner="${S1A_SOCKET_OWNER:-root}"
# Every root-owned socket found, for the verify step to re-check in a new process.
socket_list="${S1A_SOCKET_LIST:-${RUNNER_TEMP:?}/r13-sockets.txt}"

user="$(id -un)"
if [ "$user" = root ]; then echo "::error::drop-sudo must run as the runner user, not root"; exit 1; fi
if ! [[ "$user" =~ ^[a-z_][a-z0-9_-]*$ ]]; then echo "::error::unexpected user name"; exit 1; fi
if ! sudo -n true; then echo "::error::sudo does not work before the drop, so the drop cannot be verified"; exit 1; fi

# 1. Root-owned sockets this process can still write through groups it already holds (Docker,
#    containerd). Group removal in step 2 affects only new logins, so a named-user ACL entry,
#    which takes precedence over group entries, denies this user now. The scan runs as root, so
#    no directory the user cannot list hides a socket, and a failed scan stops the script.
found="$(mktemp)"
sudo find "$run" -xdev -type s -user "$socket_owner" -print0 > "$found"
: > "$socket_list"
while IFS= read -r -d '' sock; do
  printf '%s\n' "$sock" >> "$socket_list"
  if [ -w "$sock" ]; then
    sudo setfacl -m "u:${user}:---" "$sock"
    echo "closed socket $sock"
  fi
done < "$found"
rm -f "$found"

# 2. Privileged groups, for any later login.
for group in sudo admin adm docker lxd; do
  members="$(getent group "$group" | cut -d: -f4 || true)"
  if printf '%s\n' "${members//,/$'\n'}" | grep -qx "$user"; then
    sudo gpasswd -d "$user" "$group" >/dev/null
    echo "removed $user from $group"
  fi
done

# 3. sudoers rules naming the user directly. Every edit is planned and validated first, then all
#    are applied in one privileged call: the first write removes this user's own rule, so no later
#    sudo call would work. A read failure stops the script rather than writing an empty file.
pairs=()
plan() {
  local file="$1" orig new
  orig="$(mktemp)"
  new="$(mktemp)"
  sudo cat "$file" > "$orig"
  grep -Ev "^[[:space:]]*${user}[[:space:]]" "$orig" > "$new" || true
  if cmp -s "$orig" "$new"; then
    rm -f "$new"
  else
    sudo visudo -cqf "$new"
    pairs+=("$file" "$new")
  fi
  rm -f "$orig"
}
plan "$etc/sudoers"
for f in "$etc"/sudoers.d/*; do
  if [ -f "$f" ]; then plan "$f"; fi
done
if [ "${#pairs[@]}" -gt 0 ]; then
  sudo sh -c 'while [ "$#" -gt 1 ]; do cat "$2" > "$1" && chmod 0440 "$1" || exit 1; echo "stripped $1"; shift 2; done' sh "${pairs[@]}"
  for ((i = 1; i < ${#pairs[@]}; i += 2)); do rm -f "${pairs[$i]}"; done
fi

# 4. Forget any cached credential, then require that sudo now fails.
sudo -K || true
if sudo -n true 2>/dev/null; then echo "::error::sudo still works after the drop"; exit 1; fi
echo "drop_sudo=done"
