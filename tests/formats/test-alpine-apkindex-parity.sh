#!/usr/bin/env bash
# test-alpine-apkindex-parity.sh - the APKINDEX a hosted Alpine repo generates
# for real upstream packages carries the same stanza as upstream's own index,
# whichever upload route the package arrived by, and a real apk client
# resolves from it (artifact-keeper#5254).
#
# Packages: real ones from the upstream Alpine branch (default
# https://dl-cdn.alpinelinux.org/alpine v3.24/main/x86_64), picked by NAME so
# the suite follows upstream version bumps:
#   nginx         plain package, k:100
#   nginx-doc     install_if (i:docs nginx=<ver>), k:100
#   postgresql18  provider_priority (k:18) for the virtual name `postgresql`
#
# Each package is uploaded twice, into two hosted Alpine repos:
#   native   PUT /alpine/{repo}/{branch}/{repo}/{arch}/{file}
#   generic  PUT /api/v1/repositories/{repo}/artifacts/{branch}/{repo}/{arch}/{file}
#
# Oracles:
#   1. Field parity. For every uploaded package, every field upstream's
#      APKINDEX stanza carries must be in the generated stanza with the same
#      value. List-valued fields (D: p: i: r:) compare as token sets, so only
#      token order may differ.
#   2. Artifact record identity. The generic upload's artifact row names the
#      package (name/version), as the native upload's does.
#   3. A real apk client (apk.static from upstream's apk-tools-static, run in
#      --usermode against a scratch root, no root and no docker needed):
#        - `apk add --simulate nginx` plans nginx
#        - `apk add --simulate postgresql` plans postgresql18 (needs k:)
#        - `apk add --simulate nginx docs` plans nginx-doc (needs i:)
#        - `apk fetch nginx` with the AK repo as the ONLY repository
#          downloads bytes identical to upstream's file
#      The simulate cases also read a local "deps" index: upstream's index
#      minus the packages under test and minus any other provider of their
#      plain virtual names (postgresql17 also provides `postgresql`). The
#      packages under test can therefore only come from the AK repo, and their
#      dependencies resolve without uploading the whole closure.
#
# On 1.11.11 the native repo is missing k: (all three) and i: (nginx-doc), so
# `apk add postgresql` stops at "please select one of the 'provided by'
# packages explicitly"; the generic repo lists every package as P:v3.24
# V:main, so every apk case is "no such package".
#
# Network: reads the upstream index, the three packages (~7 MB) and
# apk-tools-static (~3 MB) from ALPINE_MIRROR, like the other *-remote suites
# read their public upstreams. To run offline, set ALPINE_PKG_CACHE to a
# directory holding APKINDEX.tar.gz, the package files and the
# apk-tools-static .apk (any file missing there is fetched), or set
# APK_STATIC to an apk.static binary.
#
# Env: BASE_URL ADMIN_USER ADMIN_PASS RUN_ID (common.sh), ALPINE_MIRROR,
#      ALPINE_BRANCH, ALPINE_REPOSITORY, ALPINE_ARCH, ALPINE_PKG_CACHE,
#      APK_STATIC, KEEP_REPOS=1 (leave the repos behind for inspection).
#
# Requires: curl, jq, tar, gzip, python3, sha256sum
source "$(dirname "$0")/../lib/common.sh"

begin_suite "alpine-apkindex-parity"
require_cmd python3
require_cmd jq
require_cmd tar
auth_admin
setup_workdir

ALPINE_MIRROR="${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}"
ALPINE_BRANCH="${ALPINE_BRANCH:-v3.24}"
ALPINE_REPOSITORY="${ALPINE_REPOSITORY:-main}"
ALPINE_ARCH="${ALPINE_ARCH:-x86_64}"
ALPINE_PKG_CACHE="${ALPINE_PKG_CACHE:-}"

LAYOUT="${ALPINE_BRANCH}/${ALPINE_REPOSITORY}/${ALPINE_ARCH}"
UPSTREAM_DIR="${ALPINE_MIRROR%/}/${LAYOUT}"

PKG_PLAIN="nginx"
PKG_INSTALL_IF="nginx-doc"
PKG_PRIORITY="postgresql18"
VIRTUAL_NAME="postgresql"
INSTALL_IF_TRIGGER="docs"
PKGS=("$PKG_PLAIN" "$PKG_INSTALL_IF" "$PKG_PRIORITY")

NAT="test-alp-par-nat-${RUN_ID}"
GEN="test-alp-par-gen-${RUN_ID}"

if [ "${KEEP_REPOS:-0}" != "1" ]; then
  add_exit_handler "curl -s -o /dev/null -X DELETE -H \"\$(auth_header)\" \"\${BASE_URL}/api/v1/repositories/${NAT}\" || true"
  add_exit_handler "curl -s -o /dev/null -X DELETE -H \"\$(auth_header)\" \"\${BASE_URL}/api/v1/repositories/${GEN}\" || true"
fi

UP_DIR="${WORK_DIR}/upstream"
mkdir -p "$UP_DIR"

# fetch_upstream FILE: copy FILE from ALPINE_PKG_CACHE or download it from the
# mirror into UP_DIR. Returns non-zero if neither source has it.
fetch_upstream() {
  local f="$1"
  [ -s "${UP_DIR}/${f}" ] && return 0
  if [ -n "$ALPINE_PKG_CACHE" ] && [ -s "${ALPINE_PKG_CACHE}/${f}" ]; then
    cp "${ALPINE_PKG_CACHE}/${f}" "${UP_DIR}/${f}"
    return 0
  fi
  curl -sf --max-time 300 --connect-timeout 15 -o "${UP_DIR}/${f}" "${UPSTREAM_DIR}/${f}"
}

# apkindex_py SUBCOMMAND ARGS... - stanza-level operations on APKINDEX text.
#   file NAME INDEX            print "<P>-<V>.apk" for package NAME
#   field NAME FIELD INDEX     print one field of NAME's stanza
#   names INDEX                print every P: value, one per line
#   parity NAME UPSTREAM OURS  exit 0 when OURS' stanza for NAME carries every
#                              upstream field with the same value; otherwise
#                              print what differs and exit 1
#   deps UPSTREAM OUT NAME...  write UPSTREAM minus NAME... and minus every
#                              other provider of their plain p: names
apkindex_py() {
  python3 -I - "$@" <<'PY'
import sys

LIST_FIELDS = set("Dpir")

def parse(path):
    stanzas = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for block in fh.read().split("\n\n"):
            fields = {}
            order = []
            for line in block.splitlines():
                if len(line) >= 2 and line[1] == ":":
                    fields[line[0]] = line[2:]
                    order.append(line[0])
            if "P" in fields:
                stanzas.append((fields, order))
    return stanzas

def find(stanzas, name):
    return [f for f, _ in stanzas if f.get("P") == name]

def norm(key, value):
    return sorted(value.split()) if key in LIST_FIELDS else value

cmd, args = sys.argv[1], sys.argv[2:]
if cmd == "file":
    hits = find(parse(args[1]), args[0])
    if not hits:
        sys.exit(1)
    print("%s-%s.apk" % (hits[0]["P"], hits[0]["V"]))
elif cmd == "field":
    hits = find(parse(args[2]), args[0])
    if not hits or args[1] not in hits[0]:
        sys.exit(1)
    print(hits[0][args[1]])
elif cmd == "names":
    for f, _ in parse(args[0]):
        print(f["P"])
elif cmd == "parity":
    name, up_path, ours_path = args
    up = find(parse(up_path), name)
    ours_all = parse(ours_path)
    ours = find(ours_all, name)
    if not up:
        print("upstream index has no stanza P:%s" % name)
        sys.exit(2)
    if not ours:
        names = sorted({f["P"] for f, _ in ours_all})
        print("generated index has no stanza P:%s (its P: values: %s)"
              % (name, ", ".join(names) or "<none>"))
        sys.exit(1)
    if len(ours) > 1:
        print("generated index has %d stanzas P:%s" % (len(ours), name))
        sys.exit(1)
    up, ours = up[0], ours[0]
    problems = []
    for key in sorted(up):
        if key not in ours:
            problems.append("missing %s:%s" % (key, up[key]))
        elif norm(key, up[key]) != norm(key, ours[key]):
            problems.append("%s: upstream=[%s] ours=[%s]" % (key, up[key], ours[key]))
    extra = sorted(set(ours) - set(up))
    if problems:
        print("; ".join(problems))
        sys.exit(1)
    if extra:
        print("note: fields upstream does not carry: %s" % ", ".join(extra))
elif cmd == "deps":
    up_path, out_path, names = args[0], args[1], set(args[2:])
    stanzas = parse(up_path)
    virtuals = set()
    for f, _ in stanzas:
        if f["P"] in names:
            virtuals |= {t.split("=")[0] for t in f.get("p", "").split() if ":" not in t}
    kept = []
    for f, order in stanzas:
        provides = {t.split("=")[0] for t in f.get("p", "").split()}
        if f["P"] in names or provides & virtuals:
            continue
        kept.append("\n".join("%s:%s" % (k, f[k]) for k in order))
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n\n".join(kept) + "\n\n")
else:
    sys.exit("unknown subcommand %s" % cmd)
PY
}

# ---------------------------------------------------------------------------
# Setup: upstream index, packages, apk.static
# ---------------------------------------------------------------------------

begin_test "Setup: upstream ${LAYOUT} index and packages"
UP_INDEX="${UP_DIR}/APKINDEX"
setup_ok=1
setup_msg=""
if fetch_upstream "APKINDEX.tar.gz" && tar -xzOf "${UP_DIR}/APKINDEX.tar.gz" APKINDEX > "$UP_INDEX" 2>/dev/null \
   && [ -s "$UP_INDEX" ]; then
  declare -A FILE_OF VER_OF
  for p in "${PKGS[@]}"; do
    f=$(apkindex_py file "$p" "$UP_INDEX") || { setup_ok=0; setup_msg="${setup_msg} upstream index has no ${p};"; continue; }
    FILE_OF[$p]="$f"
    VER_OF[$p]=$(apkindex_py field "$p" V "$UP_INDEX")
    want_size=$(apkindex_py field "$p" S "$UP_INDEX")
    if ! fetch_upstream "$f"; then
      setup_ok=0; setup_msg="${setup_msg} could not fetch ${f};"
    elif [ "$(wc -c < "${UP_DIR}/${f}" | tr -d ' ')" != "$want_size" ]; then
      setup_ok=0; setup_msg="${setup_msg} ${f} is not the S:${want_size} bytes the index lists;"
    fi
  done
  # The packages must still carry the fields this suite is about.
  apkindex_py field "$PKG_PRIORITY" k "$UP_INDEX" >/dev/null \
    || { setup_ok=0; setup_msg="${setup_msg} upstream ${PKG_PRIORITY} has no k:;"; }
  apkindex_py field "$PKG_PRIORITY" p "$UP_INDEX" | tr ' ' '\n' | grep -qx "$VIRTUAL_NAME" \
    || { setup_ok=0; setup_msg="${setup_msg} upstream ${PKG_PRIORITY} no longer provides ${VIRTUAL_NAME};"; }
  apkindex_py field "$PKG_INSTALL_IF" i "$UP_INDEX" | grep -q "$INSTALL_IF_TRIGGER" \
    || { setup_ok=0; setup_msg="${setup_msg} upstream ${PKG_INSTALL_IF} has no i: on ${INSTALL_IF_TRIGGER};"; }
else
  setup_ok=0
  setup_msg="could not read ${UPSTREAM_DIR}/APKINDEX.tar.gz (or ALPINE_PKG_CACHE)"
fi
if [ "$setup_ok" = 1 ]; then
  for p in "${PKGS[@]}"; do echo "  ${p}: ${FILE_OF[$p]}"; done
  pass
else
  infra_fail "upstream fixture precondition not met:${setup_msg}"
  end_suite
fi

begin_test "Setup: apk.static client"
APK="${APK_STATIC:-}"
if [ -z "$APK" ]; then
  tools_file=$(apkindex_py file apk-tools-static "$UP_INDEX" || true)
  if [ -n "$tools_file" ] && fetch_upstream "$tools_file"; then
    mkdir -p "${WORK_DIR}/apk-tools"
    tar -xzf "${UP_DIR}/${tools_file}" -C "${WORK_DIR}/apk-tools" sbin/apk.static 2>/dev/null || true
    APK="${WORK_DIR}/apk-tools/sbin/apk.static"
  fi
fi
if [ -n "$APK" ] && [ -x "$APK" ] && apk_ver=$("$APK" --version 2>/dev/null); then
  echo "  ${apk_ver}"
  pass
else
  infra_fail "no runnable apk.static (APK_STATIC='${APK_STATIC:-}', upstream apk-tools-static '${tools_file:-}')"
  end_suite
fi

# apk_in ROOT ARGS...: run apk.static against a scratch root, as this user,
# reading only the repositories named with -X. --usermode (commit applets
# only) lets `add` work without root; `fetch` refuses it and does not need it.
apk_in() {
  local root="$1"; shift
  local usermode="--usermode"
  case " $* " in *" fetch "*) usermode="" ;; esac
  timeout 300 "$APK" $usermode --root "$root" --arch "$ALPINE_ARCH" --allow-untrusted \
    --no-cache --no-interactive --repositories-file /dev/null "$@"
}

# new_root NAME: an empty initialised apk database.
new_root() {
  local root="${WORK_DIR}/root-$1"
  rm -rf "$root"; mkdir -p "$root"
  apk_in "$root" --initdb add >/dev/null 2>&1 || return 1
  echo "$root"
}

begin_test "Setup: local deps index (upstream minus the packages under test)"
DEPS_REPO="${WORK_DIR}/deps-repo"
mkdir -p "${DEPS_REPO}/${ALPINE_ARCH}"
if apkindex_py deps "$UP_INDEX" "${WORK_DIR}/APKINDEX" "${PKGS[@]}" \
   && (cd "$WORK_DIR" && tar -czf "${DEPS_REPO}/${ALPINE_ARCH}/APKINDEX.tar.gz" APKINDEX) \
   && probe_root=$(new_root probe) \
   && probe=$(apk_in "$probe_root" -X "$DEPS_REPO" add --simulate "$INSTALL_IF_TRIGGER" 2>&1); then
  removed=$(( $(apkindex_py names "$UP_INDEX" | wc -l) - $(apkindex_py names "${WORK_DIR}/APKINDEX" | wc -l) ))
  echo "  ${removed} stanzas removed; deps index resolves '${INSTALL_IF_TRIGGER}'"
  pass
else
  infra_fail "could not build or read the local deps index" "${probe:-}"
  end_suite
fi

# ---------------------------------------------------------------------------
# Repositories and uploads
# ---------------------------------------------------------------------------

begin_test "Create hosted Alpine repos (native and generic upload)"
if create_local_repo "$NAT" alpine && create_local_repo "$GEN" alpine; then
  pass
else
  fail_fatal "could not create ${NAT} / ${GEN}"
fi

begin_test "Upload the packages on the native route"
bad=""
for p in "${PKGS[@]}"; do
  f="${FILE_OF[$p]}"
  st=$(curl -s -o "${WORK_DIR}/nat-${p}.json" -w '%{http_code}' --max-time 300 -X PUT \
    -H "$(format_auth_header)" -H "Content-Type: application/octet-stream" \
    --data-binary "@${UP_DIR}/${f}" "${BASE_URL}/alpine/${NAT}/${LAYOUT}/${f}") || st=000
  [[ "$st" =~ ^2 ]] || bad="${bad} ${f}=${st}"
done
if [ -z "$bad" ]; then pass; else fail_fatal "native PUT failed:${bad}"; fi

begin_test "Upload the packages on the generic artifact route"
bad=""
for p in "${PKGS[@]}"; do
  f="${FILE_OF[$p]}"
  st=$(curl -s -o "${WORK_DIR}/gen-${p}.json" -w '%{http_code}' --max-time 300 -X PUT \
    -H "$(auth_header)" -H "Content-Type: application/x-tar" \
    --data-binary "@${UP_DIR}/${f}" "${BASE_URL}/api/v1/repositories/${GEN}/artifacts/${LAYOUT}/${f}") || st=000
  [[ "$st" =~ ^2 ]] || bad="${bad} ${f}=${st}"
done
if [ -z "$bad" ]; then pass; else fail_fatal "generic PUT failed:${bad}"; fi

# fetch_index REPO: the generated APKINDEX text, at ${WORK_DIR}/<repo>.APKINDEX
fetch_index() {
  local repo="$1" out="${WORK_DIR}/$1.APKINDEX"
  local st
  st=$(curl -s -o "${WORK_DIR}/$1.tar.gz" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" "${BASE_URL}/alpine/${repo}/${LAYOUT}/APKINDEX.tar.gz") || st=000
  [ "$st" = 200 ] && tar -xzOf "${WORK_DIR}/$1.tar.gz" APKINDEX > "$out" 2>/dev/null && [ -s "$out" ]
}

begin_test "Generated APKINDEX.tar.gz readable for both repos"
if fetch_index "$NAT" && fetch_index "$GEN"; then
  pass
else
  fail_fatal "GET ${LAYOUT}/APKINDEX.tar.gz did not return a readable index for ${NAT} and ${GEN}"
fi

# ---------------------------------------------------------------------------
# 1. Field parity against upstream's stanza
# ---------------------------------------------------------------------------

for route in native generic; do
  repo="$NAT"; [ "$route" = generic ] && repo="$GEN"
  for p in "${PKGS[@]}"; do
    begin_test "${route} upload: ${p} stanza carries every upstream APKINDEX field"
    if out=$(apkindex_py parity "$p" "$UP_INDEX" "${WORK_DIR}/${repo}.APKINDEX"); then
      [ -n "$out" ] && echo "  ${out}"
      pass
    else
      fail "${out}" "$(awk -v p="$p" 'BEGIN{RS="";FS="\n"} $0 ~ "(^|\n)P:" p "(\n|$)"' "$UP_INDEX" | sed 's/^/upstream  /')"
    fi
  done
done

# ---------------------------------------------------------------------------
# 2. Artifact record identity of the generic upload
# ---------------------------------------------------------------------------

begin_test "generic upload: artifact records carry the package name and version"
bad=""
for p in "${PKGS[@]}"; do
  got=$(jq -r '"\(.name)/\(.version)"' "${WORK_DIR}/gen-${p}.json" 2>/dev/null || echo "?")
  [ "$got" = "${p}/${VER_OF[$p]}" ] || bad="${bad} ${FILE_OF[$p]}: name/version=${got};"
done
if [ -z "$bad" ]; then pass; else fail "expected <pkgname>/<pkgver>:${bad}"; fi

# ---------------------------------------------------------------------------
# 3. A real apk client
# ---------------------------------------------------------------------------

encpw=$(printf '%s' "$ADMIN_PASS" | jq -sRr @uri)
encuser=$(printf '%s' "$ADMIN_USER" | jq -sRr @uri)
ak_repo_url() { echo "${BASE_URL/:\/\//://${encuser}:${encpw}@}/alpine/$1/${ALPINE_BRANCH}/${ALPINE_REPOSITORY}"; }

# plans OUTPUT NAME VERSION: the simulated transaction installs NAME VERSION.
plans() { grep -qE "Installing $2 \($(printf '%s' "$3" | sed 's/[.]/\\./g')\)" <<<"$1"; }

for route in native generic; do
  repo="$NAT"; [ "$route" = generic ] && repo="$GEN"
  url=$(ak_repo_url "$repo")

  begin_test "${route} upload: apk add ${PKG_PLAIN} resolves it from the AK repo"
  root=$(new_root "${route}-plain") || root="${WORK_DIR}/no-root"
  out=$(apk_in "$root" -X "$url" -X "$DEPS_REPO" add --simulate "$PKG_PLAIN" 2>&1) || true
  if plans "$out" "$PKG_PLAIN" "${VER_OF[$PKG_PLAIN]}"; then
    pass
  else
    fail "apk add --simulate ${PKG_PLAIN} did not plan ${PKG_PLAIN} ${VER_OF[$PKG_PLAIN]}" "$out"
  fi

  begin_test "${route} upload: apk add ${VIRTUAL_NAME} selects ${PKG_PRIORITY} by provider_priority (k:)"
  root=$(new_root "${route}-virtual") || root="${WORK_DIR}/no-root"
  out=$(apk_in "$root" -X "$url" -X "$DEPS_REPO" add --simulate "$VIRTUAL_NAME" 2>&1) || true
  if plans "$out" "$PKG_PRIORITY" "${VER_OF[$PKG_PRIORITY]}"; then
    pass
  else
    fail "apk add --simulate ${VIRTUAL_NAME} did not plan ${PKG_PRIORITY} ${VER_OF[$PKG_PRIORITY]}" "$out"
  fi

  begin_test "${route} upload: apk add ${PKG_PLAIN} ${INSTALL_IF_TRIGGER} pulls in ${PKG_INSTALL_IF} by install_if (i:)"
  root=$(new_root "${route}-installif") || root="${WORK_DIR}/no-root"
  out=$(apk_in "$root" -X "$url" -X "$DEPS_REPO" add --simulate "$PKG_PLAIN" "$INSTALL_IF_TRIGGER" 2>&1) || true
  if plans "$out" "$PKG_INSTALL_IF" "${VER_OF[$PKG_INSTALL_IF]}"; then
    pass
  else
    fail "apk add --simulate ${PKG_PLAIN} ${INSTALL_IF_TRIGGER} did not plan ${PKG_INSTALL_IF} ${VER_OF[$PKG_INSTALL_IF]}" "$out"
  fi

  begin_test "${route} upload: apk fetch ${PKG_PLAIN} from the AK repo alone returns upstream's bytes"
  root=$(new_root "${route}-fetch") || root="${WORK_DIR}/no-root"
  dl="${WORK_DIR}/fetch-${route}"
  mkdir -p "$dl"
  out=$(apk_in "$root" -X "$url" fetch -o "$dl" "$PKG_PLAIN" 2>&1) || true
  f="${FILE_OF[$PKG_PLAIN]}"
  if [ -s "${dl}/${f}" ] && [ "$(sha256sum < "${dl}/${f}")" = "$(sha256sum < "${UP_DIR}/${f}")" ]; then
    pass
  else
    fail "apk fetch ${PKG_PLAIN} did not download ${f} identical to upstream" "$out"
  fi
done

end_suite
