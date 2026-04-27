#!/usr/bin/env bash
# Module F: Sandbox / isolation
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="F"
log "$MODULE" "Starting sandbox/isolation audit..."
> "$FINDINGS_DIR/$MODULE.jsonl"

# Detect if running in a container / VM
in_container=0
if [[ -f /.dockerenv ]] || grep -q docker /proc/1/cgroup 2>/dev/null; then
  in_container=1
  emit_finding "$MODULE" "INFO" "F.container" "Running inside Docker container" "" "" ""
fi
if [[ -n "${CODESPACES:-}" || -n "${REMOTE_CONTAINERS_IPC:-}" ]]; then
  in_container=1
  emit_finding "$MODULE" "INFO" "F.devcontainer" "Running inside devcontainer / Codespaces" "" "" ""
fi

# WSL on Linux
if [[ "$OS" == "linux" && -n "${WSL_DISTRO_NAME:-}" ]]; then
  emit_finding "$MODULE" "INFO" "F.wsl" "Running in WSL ($WSL_DISTRO_NAME)" "" "" ""
fi

if [[ "$in_container" -eq 0 ]]; then
  emit_finding "$MODULE" "MEDIUM" "F.bare" \
    "Running on bare host (no container/VM/WSL detected)" \
    "AI agent has access to the actual user's \$HOME with all credentials. The Nx-style attack assumes exactly this." \
    "Run AI tools in devcontainers when possible. VSCode Remote-Containers, Distrobox on Linux, OrbStack/Docker on macOS." \
    "Nx s1ngularity — agents on bare hosts harvested everything in \$HOME"
fi

# Group memberships — docker, sudo, wheel, admin
groups_out=$(id -Gn 2>/dev/null || echo "")
for grp in docker sudo wheel admin; do
  if echo "$groups_out" | grep -qw "$grp"; then
    if [[ "$grp" == "docker" ]]; then
      emit_finding "$MODULE" "HIGH" "F.docker" \
        "Current user is in 'docker' group" \
        "Membership in docker group is equivalent to passwordless root: 'docker run --privileged -v /:/host alpine'." \
        "If you don't actively use Docker, leave the group: sudo gpasswd -d \$USER docker. Otherwise be aware that AI agent with shell access has effective root." \
        ""
    elif [[ "$grp" == "sudo" || "$grp" == "wheel" || "$grp" == "admin" ]]; then
      emit_finding "$MODULE" "INFO" "F.sudo" \
        "User is in '$grp' group (can sudo)" \
        "Sudo cache (~5min after sudo) means agent could 'sudo X' without password during that window." \
        "Reduce sudo timeout in /etc/sudoers: Defaults timestamp_timeout=0 (require password every time)." \
        ""
    fi
  fi
done

# sudo cache state
if has sudo; then
  if sudo -n true 2>/dev/null; then
    emit_finding "$MODULE" "HIGH" "F.sudocache" \
      "Sudo password is currently cached" \
      "Right now, any process running as this user can run sudo without password prompt." \
      "Clear cache immediately: sudo -k. Reduce timestamp_timeout in /etc/sudoers." \
      ""
  fi
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
