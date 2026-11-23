#!/usr/bin/env bash
# =============================================================================
# fixtures/conda/gen-channel.sh: a deterministic conda channel at scale
# (artifact-keeper#4187)
# =============================================================================
# Usage:
#   gen-channel.sh [--names N] [--versions V] [--builds B]
#                  [--subdirs linux-64,noarch] [--deps-per-package D]
#                  [--seed S] [--formats mixed|conda|tar.bz2]
#                  [--locks 1000,2000,3000] [--channel-url URL]
#                  [--jobs J] --out DIR
#   gen-channel.sh locks --channel DIR --channel-url URL [--sizes 1000,...] --out DIR
#
# Writes DIR/<subdir>/{repodata.json,*.conda,*.tar.bz2}, DIR/locks/env-<k>/
# {pixi.lock,explicit.txt,urls.tsv} and DIR/MANIFEST.sha256. Same arguments
# and seed, same bytes (fixed archive timestamps, owners and member order).
# Each package's info/index.json `depends` names D other fixture packages
# with version bounds, so a solver must walk the graph; each package links
# share/<name>/marker.txt for fc_assert-style install checks. Every name gets
# V x B artifacts; builds alternate between .conda and .tar.bz2 (--formats
# mixed), so each lock carries both formats.
#
# Generated at test time into a temp dir; nothing large is committed.
#
# Cache: with CONDA_FIXTURE_CACHE=<dir> set (the release gate sets it once per
# CI run, defaulting to $RUNNER_TEMP/conda-fixtures), a channel is generated
# once per (arguments, generator source) key and reused by later tiers in
# the run: DIR becomes a copy (hard links when possible) of the cached tree.
#
# Python: the stdlib generator needs compression.zstd (Python 3.14+) for
# .conda. Without it on the host, it runs in python:3.14-slim
# (GEN_CHANNEL_IMAGE overrides), so the bytes come from one pinned toolchain.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${HERE}/gen_channel.py"
IMAGE="${GEN_CHANNEL_IMAGE:-python:3.14-slim}"

sub="channel"
if [ "${1:-}" = "locks" ] || [ "${1:-}" = "package" ]; then sub="$1"; shift; fi

# Find --out (and --channel for locks) so the container can mount them.
out="" channel=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    --out) out="${args[$((i + 1))]:-}" ;;
    --out=*) out="${args[$i]#--out=}" ;;
    --channel) channel="${args[$((i + 1))]:-}" ;;
    --channel=*) channel="${args[$i]#--channel=}" ;;
  esac
done
[ -n "$out" ] || { echo "gen-channel.sh: --out DIR is required" >&2; exit 2; }
mkdir -p "$out"
out="$(cd "$out" && pwd)"
[ -z "$channel" ] || channel="$(cd "$channel" && pwd)"
# The same arguments with --out/--channel made absolute (the container's
# working directory is not the caller's).
norm=()
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    --out) norm+=(--out "$out"); i=$((i + 1)) ;;
    --out=*) norm+=(--out "$out") ;;
    --channel) norm+=(--channel "$channel"); i=$((i + 1)) ;;
    --channel=*) norm+=(--channel "$channel") ;;
    *) norm+=("${args[$i]}") ;;
  esac
done

host_python_ok() {
  command -v python3 >/dev/null 2>&1 && python3 -c 'import compression.zstd' >/dev/null 2>&1
}

run_py() {
  if [ "${GEN_CHANNEL_FORCE_DOCKER:-0}" != "1" ] && host_python_ok; then
    python3 -I "$PY" "$@"
    return
  fi
  command -v docker >/dev/null 2>&1 || {
    echo "gen-channel.sh: needs Python 3.14+ (compression.zstd) or docker" >&2; exit 3; }
  local mounts=(-v "${HERE}:/gen:ro" -v "${out}:${out}")
  [ -z "$channel" ] || [ "$channel" = "$out" ] || mounts+=(-v "${channel}:${channel}:ro")
  docker run --rm --security-opt label=disable --user "$(id -u):$(id -g)" \
    "${mounts[@]}" "$IMAGE" python3 -I /gen/gen_channel.py "$@"
}

if [ "$sub" != "channel" ] || [ -z "${CONDA_FIXTURE_CACHE:-}" ]; then
  run_py "$sub" "${norm[@]}"
  exit 0
fi

# --- cached channel generation ------------------------------------------------
# Key: the generator source plus every argument except --out.
key_args=()
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    --out) i=$((i + 1)) ;;
    --out=*) ;;
    *) key_args+=("${args[$i]}") ;;
  esac
done
key="$( { cat "$PY"; printf '%s\n' "${key_args[@]}"; } | sha256sum | cut -c1-16)"
cache="${CONDA_FIXTURE_CACHE%/}/channel-${key}"
if [ ! -f "${cache}/MANIFEST.sha256" ]; then
  mkdir -p "${CONDA_FIXTURE_CACHE}"
  tmp="$(mktemp -d "${CONDA_FIXTURE_CACHE%/}/.gen-${key}.XXXXXX")"
  saved_out="$out"; out="$tmp"
  run_py channel "${key_args[@]}" --out "$tmp" > "${tmp}.summary"
  out="$saved_out"
  # Another tier may have won the race; either copy is the same bytes.
  if mv -T "$tmp" "$cache" 2>/dev/null; then mv "${tmp}.summary" "${cache}.summary"
  else rm -rf "$tmp" "${tmp}.summary"; fi
  echo "gen-channel.sh: generated ${cache}" >&2
else
  echo "gen-channel.sh: cache hit ${cache}" >&2
fi
cp -al "${cache}/." "$out/" 2>/dev/null || cp -a "${cache}/." "$out/"
cat "${cache}.summary" 2>/dev/null || true
