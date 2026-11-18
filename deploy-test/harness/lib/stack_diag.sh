#!/usr/bin/env bash
# =============================================================================
# harness/lib/stack_diag.sh — what run.sh prints and decides when a tier's
# compose stack does not come up healthy (artifact-keeper-test#890)
# =============================================================================
# WHY THIS EXISTS
# In the 1.12.0 candidate the OpenLDAP fixture (ak-dtf1-ldap) exited 1 right
# after it started, the backend never started, and the tier went red as
# "stack-up: candidate/sidecar never healthy". run.sh printed only the
# backend's log tail (empty: it never ran) and then `down -v` removed the
# fixture, so the cause was gone with it. The same service came up fine for
# the next tier in the same job.
#
#   dtf_dump_stack <project>
#       Before teardown: one state line per container in the compose project
#       (status, health, exit code, OOMKilled, error), then, for every
#       container that is not healthy, its `docker logs --tail 200` and its
#       last healthcheck results. Applies to every tier, not just LDAP.
#
#   dtf_fixture_crash_only <project> <candidate-image> [<candidate-image> ...]
#       Exit 0, printing "<name> exited <code>" for each crashed fixture, when
#       the failure is PROVABLY not the candidate's: at least one fixture
#       exited non-zero, and every candidate container is still in state
#       `created`, i.e. compose never started it because a dependency failed.
#       A container is a candidate when its image ref equals a candidate
#       image, when its image REPOSITORY (tag and digest stripped) equals a
#       candidate's, or when its compose service name contains "backend"
#       (backend, backend-b, peer-backend, ...). Everything else is a fixture.
#       Anything else (a candidate that ran and went unhealthy or exited, no
#       candidate container found, no fixture crash) exits 1 and the failure
#       stays a stack-up FAIL. run.sh retries the stack once on exit 0 and,
#       if the retry fails the same test again (some fixture, not necessarily
#       the same one, exited non-zero while every candidate container was
#       still `created`), reports the tier as INFRA (DTF_EXIT_INFRA), never as
#       a regression: nothing ran against the candidate.
# =============================================================================

DTF_DIAG_LOG_TAIL="${DTF_DIAG_LOG_TAIL:-200}"

# One container name per line, every container compose created for <project>.
dtf_stack_containers() {
  docker ps -a --filter "label=com.docker.compose.project=$1" --format '{{.Names}}' 2>/dev/null | sort
}

# "<status>|<health or none>|<exit code>|<image>|<compose service>" for one
# container.
dtf_container_state() {
  docker inspect -f '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.ExitCode}}|{{.Config.Image}}|{{index .Config.Labels "com.docker.compose.service"}}' "$1" 2>/dev/null
}

# A container is fine when it runs and is healthy (or has no healthcheck), or
# when it is a one-shot that exited 0. Args: status health exit.
dtf_state_ok() {
  case "$1:$2" in
    running:healthy|running:none) return 0 ;;
    exited:*) [ "$3" = "0" ] && return 0 ;;
  esac
  return 1
}

dtf_dump_stack() {
  local project="$1" c state status health code image
  local ctrs=()
  mapfile -t ctrs < <(dtf_stack_containers "$project")
  echo "== stack state, project ${project} (artifact-keeper-test#890) =="
  if [ ${#ctrs[@]} -eq 0 ] || [ -z "${ctrs[0]}" ]; then
    echo "   (no containers found for the project)"
    return 0
  fi
  for c in "${ctrs[@]}"; do
    printf '   %-36s %s\n' "$c" \
      "$(docker inspect -f 'status={{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{.State.Error}}' "$c" 2>/dev/null || echo '<inspect failed>')"
  done
  for c in "${ctrs[@]}"; do
    state="$(dtf_container_state "$c")"
    IFS='|' read -r status health code image _ <<< "$state"
    dtf_state_ok "$status" "$health" "$code" && continue
    echo ""
    echo "== ${c} (${image}): ${status}, health ${health}, exit ${code} =="
    echo "-- docker inspect: ExitCode Error OOMKilled"
    docker inspect -f '{{.State.ExitCode}} {{.State.Error}} {{.State.OOMKilled}}' "$c" 2>&1 || true
    if [ "$health" != "none" ]; then
      echo "-- last healthcheck results"
      docker inspect -f '{{range .State.Health.Log}}{{.ExitCode}}: {{.Output}}{{println}}{{end}}' "$c" 2>&1 | tail -n 20 || true
    fi
    if [ "$status" = "created" ]; then
      echo "-- never started (compose did not start it; a dependency failed)"
    else
      echo "-- docker logs --tail ${DTF_DIAG_LOG_TAIL}"
      docker logs --tail "$DTF_DIAG_LOG_TAIL" "$c" 2>&1 || true
    fi
  done
  echo "== end stack state =="
}

# Image repository without tag or digest, and without docker.io[/library]/,
# so "docker.io/library/x:1@sha256:..." and "x:2" both give "x".
dtf_image_repo() {
  local r="${1%%@*}" last
  last="${r##*/}"
  case "$last" in *:*) r="${r%:*}" ;; esac
  r="${r#docker.io/}"; r="${r#library/}"
  printf '%s\n' "$r"
}

dtf_fixture_crash_only() {
  local project="$1"; shift
  local c state status health code image service cand n_cand=0 is_cand crashes=()
  local ctrs=()
  mapfile -t ctrs < <(dtf_stack_containers "$project")
  for c in "${ctrs[@]}"; do
    [ -z "$c" ] && continue
    state="$(dtf_container_state "$c")" || return 1
    IFS='|' read -r status health code image service <<< "$state"
    is_cand=0
    # Belt and braces: any service named *backend* (backend, backend-b,
    # peer-backend) is the candidate, and so is any container whose image
    # repository is a candidate's, even if the recorded ref is spelled
    # differently (another tag, a digest, a docker.io/library/ prefix).
    case "$service" in *backend*) is_cand=1 ;; esac
    for cand in "$@"; do
      [ -n "$cand" ] || continue
      if [ "$image" = "$cand" ] || [ "$(dtf_image_repo "$image")" = "$(dtf_image_repo "$cand")" ]; then
        is_cand=1
      fi
    done
    if [ "$is_cand" = "1" ]; then
      n_cand=$((n_cand + 1))
      # The candidate ran: whatever went wrong may be about it.
      [ "$status" = "created" ] || return 1
    elif [ "$status" = "exited" ] && [ "$code" != "0" ]; then
      crashes+=("${c} exited ${code}")
    fi
  done
  [ "$n_cand" -gt 0 ] && [ ${#crashes[@]} -gt 0 ] || return 1
  local IFS=','
  printf '%s\n' "${crashes[*]}"
}
