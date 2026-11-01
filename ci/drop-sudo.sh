#!/usr/bin/env bash
# Remove the runner user's routes to root before any agent starts (S1a R13).
# Modelled on the behaviour openai/codex-action documents for its drop-sudo strategy; this is an
# independent implementation, stricter in one respect: rather than strip the rules it can
# recognise, it replaces the whole sudoers policy with one that grants nothing to anyone but root,
# so a grant through a group, uid, alias or include cannot survive. It runs as the runner user
# while sudo still works, and fails closed. The workflow's next step, a new process, verifies the
# result independently.
set -euo pipefail

# Test hooks only: the workflow never sets these, and the script runs before any agent exists.
etc="${S1A_ETC:-/etc}"
run="${S1A_RUN:-/run}"
socket_owner="${S1A_SOCKET_OWNER:-root}"
# Every root-owned socket found, for the verify step to re-check in a new process.
socket_list="${S1A_SOCKET_LIST:-${RUNNER_TEMP:?}/r13-sockets.txt}"

# A privilege that survived the drop. The driver judges R13 a fail on this marker alone; any other
# error leaves R13 inconclusive.
survived() { echo "::error::r13 survived: $1"; exit 1; }

# The root phase, run once under sudo. Every policy change happens here, in one privileged process,
# so no step depends on a sudo rule the step before it has just removed.
root_phase() {
  local user="$1" etc="$2" line plugins rules keyword argument
  # S1A_ROOT_PATH and S1A_ROOT_UID are test hooks; sudo's env_reset removes them on the runner.
  export LC_ALL=C PATH="${S1A_ROOT_PATH:-/usr/sbin:/usr/bin:/sbin:/bin}"
  [ "$(id -u)" = "${S1A_ROOT_UID:-0}" ] || { echo "::error::the root phase is not running as root"; exit 1; }
  [[ "$user" =~ ^[a-z_][a-z0-9_-]*$ ]] && [ "$user" != root ] || { echo "::error::unexpected user name"; exit 1; }
  [[ "$etc" == /* ]] || { echo "::error::the policy directory is not absolute"; exit 1; }

  # 1. The sudoers file must be the whole policy. Another policy plugin, a sudoers plugin given
  #    another file or plugin directory, or a sudoers source in nsswitch other than files (sss,
  #    ldap) could grant what no file shows: refuse rather than guess. sudo reads these keywords
  #    case-insensitively, and so does this check.
  if [ -e "$etc/sudo.conf" ]; then
    plugins="$(grep -iE '^[[:space:]]*(plugin|path)[[:space:]]' "$etc/sudo.conf" || true)"
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      read -r keyword argument _ <<< "$line"
      keyword="$(printf '%s' "$keyword" | tr '[:upper:]' '[:lower:]')"
      argument="$(printf '%s' "$argument" | tr '[:upper:]' '[:lower:]')"
      if [ "$keyword" = path ]; then
        [ "$argument" != plugin_dir ] || { echo "::error::sudo.conf moves the plugin directory"; exit 1; }
        continue
      fi
      [[ "$line" =~ ^[[:space:]]*[Pp][Ll][Uu][Gg][Ii][Nn][[:space:]]+(sudoers_policy|sudoers_io|sudoers_audit)[[:space:]]+(/usr/libexec/sudo/)?sudoers\.so[[:space:]]*$ ]] \
        || { echo "::error::sudo.conf loads a plugin other than the stock sudoers one, or gives it arguments"; exit 1; }
    done <<< "$plugins"
  fi
  if [ -e "$etc/nsswitch.conf" ]; then
    rules="$(grep -iE '^[[:space:]]*sudoers[[:space:]]*:' "$etc/nsswitch.conf" || true)"
    if [ -n "$rules" ] && ! [[ "$rules" =~ ^[[:space:]]*[Ss][Uu][Dd][Oo][Ee][Rr][Ss][[:space:]]*:[[:space:]]*[Ff][Ii][Ll][Ee][Ss][[:space:]]*$ ]]; then
      echo "::error::nsswitch.conf takes sudoers from a source other than files"; exit 1
    fi
  fi

  # 2. Record what sudo itself says the user may run, for the evidence: sudo's own parser covers
  #    every form a grant can take. Bounded: 40 lines of at most 200 characters.
  sudo -n -l -U "$user" 2>&1 | head -n 40 | cut -c 1-200 | sed 's/^/r13_sudo_before: /' || true

  # 3. Replace the policy. The new file is written, validated and given its mode inside root-owned
  #    /etc, then renamed over the old one, so no other process can alter it in between and sudo
  #    never sees a partial file. It includes nothing, so nothing in sudoers.d applies any more.
  new=""
  trap 'if [ -n "${new:-}" ]; then rm -f "$new"; fi' EXIT
  new="$(mktemp "$etc/.sudoers.gdf.XXXXXX")"
  printf '%s\n' "# Written by the S1a drop-sudo step: only root may use sudo." \
    "Defaults env_reset" 'Defaults secure_path="/usr/sbin:/usr/bin:/sbin:/bin"' \
    "root ALL=(ALL:ALL) ALL" > "$new"
  chown "$(id -u):$(id -g)" "$new"
  chmod 0440 "$new"
  visudo -cqf "$new"
  mv -f "$new" "$etc/sudoers"
  new=""
  echo "replaced $etc/sudoers: only root may use sudo"

  # 4. Ask sudo, as root, whether the user may still run anything. This comes before the group
  #    removal below, because sudo -l -U reads the group database: a group grant from a source
  #    that survived would be invisible once the user had left the group, though the running job
  #    still holds it.
  rules="$(sudo -n -l -U "$user" 2>&1 || true)"
  case "$rules" in
    *"may run the following"*) survived "sudo -l -U still lists commands for $user" ;;
    *"is not allowed to run sudo"*) ;;
    *) echo "::error::sudo -l -U gave no clear answer after the drop"; exit 1 ;;
  esac

  # 5. Privileged groups, for any later login. The running job keeps the groups it started with;
  #    sudo no longer honours them (step 3), and sockets are closed by user ACL entries.
  for group in sudo admin wheel adm docker lxd; do
    members="$(getent group "$group" | cut -d: -f4 || true)"
    if printf '%s\n' "${members//,/$'\n'}" | grep -qx "$user"; then
      gpasswd -d "$user" "$group" >/dev/null
      echo "removed $user from $group"
    fi
  done
}

user="$(id -un)"
if [ "$user" = root ]; then echo "::error::drop-sudo must run as the runner user, not root"; exit 1; fi
if ! [[ "$user" =~ ^[a-z_][a-z0-9_-]*$ ]]; then echo "::error::unexpected user name"; exit 1; fi
if ! sudo -n true; then echo "::error::sudo does not work before the drop, so the drop cannot be verified"; exit 1; fi

# 1. Root-owned sockets this process can still write through groups it already holds (Docker,
#    containerd). Group removal affects only new logins, so a named-user ACL entry, which takes
#    precedence over group entries, denies this user now. The scan runs as root, so no directory
#    the user cannot list hides a socket, and a failed scan stops the script. Writability is
#    judged here, with this process's own credentials, which is why this part is not in the root
#    phase.
found="$(mktemp)"
sudo -n find "$run" -xdev -type s -user "$socket_owner" -print0 > "$found"
: > "$socket_list"
while IFS= read -r -d '' sock; do
  printf '%s\n' "$sock" >> "$socket_list"
  if [ -w "$sock" ]; then
    # Linux consults a file's ACL only when its group bits, which are the ACL mask, are not empty;
    # otherwise the other bits decide and a named-user entry is ignored. Refuse that shape rather
    # than report a socket closed that is not (codex-action refuses it too).
    mode="$(stat -c %a "$sock" 2>/dev/null || stat -f %Lp "$sock")"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || { echo "::error::cannot read the mode of $sock"; exit 1; }
    if [ $(( (8#$mode >> 3) & 7 )) -eq 0 ]; then
      echo "::error::cannot close $sock with an ACL entry: its group bits are empty"; exit 1
    fi
    # -n keeps the existing mask, so no other ACL entry on the socket gains access (codex-action
    # #183). With group bits present, the named entry, checked before any group, denies this user.
    sudo -n setfacl -n -m "u:${user}:---" "$sock"
    echo "closed socket $sock"
  fi
done < "$found"
rm -f "$found"

# 2. Groups and the sudoers policy, in one privileged call. The root phase is passed as text, not
#    re-read from this file, so what runs as root is exactly what was defined above.
sudo -n -- /bin/bash -euo pipefail -c "$(declare -f survived root_phase); root_phase \"\$@\"" drop-sudo-root "$user" "$etc"

# 3. Forget any cached credential, then require, as this user, that sudo now refuses and that no
#    scanned socket is writable.
sudo -K || true
if sudo -n true 2>/dev/null; then survived "sudo -n true still succeeds"; fi
if sudo -n -l > /dev/null 2>&1; then survived "sudo -n -l still lists commands"; fi
while IFS= read -r sock; do
  if [ -w "$sock" ]; then survived "socket still writable: $sock"; fi
done < "$socket_list"
echo "drop_sudo=done"
