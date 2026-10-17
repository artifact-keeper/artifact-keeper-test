#!/usr/bin/env bash
# =============================================================================
# tiers/npm-unpublish-and-push-sync/oracle.sh — npm unpublish through the -rev
#   routes (artifact-keeper#4025) and push-peer sync fan-out for npm publish,
#   Go module upload (#4643) and same-path re-uploads (#4658)
# =============================================================================
# run.sh has stood up `storage.filesystem client.npm` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# The npm legs drive the REAL npm CLI inside ak-dtf<slot>-client-npm against
# http://backend:8080; the raw -rev probes, Go and generic legs are host curl.
#
# THE BUGS
#   #4025  none of the requests `npm unpublish` sends was routed. libnpmpublish
#          reads the 404 as "already gone" and exits 0, so the publisher sees
#          success while the version stays served and installable. The npm exit
#          code is therefore NOT the signal; every unpublish gate asserts the
#          SERVED state (packument, dist-tags, tarball GET) and the DB row.
#   #4643  npm publish and the goproxy .mod/.zip upload never queued a push
#          sync task, so push/mirror peers never received them.
#   #4658  a re-upload to an existing path keeps the artifact id; the enqueue
#          only bumped the priority of the already-completed push row, so the
#          peer never got the new bytes (versioned generic repo, or an upload
#          after a delete).
#
# THE PEER. Registration (POST /api/v1/peers) does not probe the endpoint, so
# the tier registers a peer at an unresolvable `.invalid` host. It is then set
# `online` with `backoff_until` a day out, directly in the DB: `online` because
# the delete fan-out only targets online peers, and the backoff because the
# sync worker only claims tasks for peers NOT in backoff. Every queued row
# therefore stays exactly where the enqueue left it, with no worker race. The
# sync_tasks table is the observable: (peer, artifact, task_type) is unique.
#
# Discriminating gates:
#   (CONTROL) true on BOTH images: npm publish + install round-trip; npm
#             unpublish leaves the kept version installable; a generic upload
#             to a push-subscribed repo queues a push row; a replication-tagged
#             Go upload queues nothing; an unversioned live overwrite is 409
#             and leaves the completed push row alone.
#   (FIX)     RED on 1.11.1: npm unpublish (scoped + unscoped, version + whole
#             package) removes the served version/package and its DB row; the
#             raw -rev routes answer 200/400/404 as #4727 specifies; npm
#             publish and Go .mod/.zip upload queue a push row; a versioned
#             re-upload and a delete-then-reupload re-arm the completed push
#             row to pending with a fresh retry budget.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

# common.sh enables errexit; every probe below guards its own failure so a 404
# cannot kill the oracle mid-suite without a JUnit case.

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT}"
NPM_CTR="ak-dtf${SLOT}-client-npm"
AUTH="${ADMIN_USER}:${ADMIN_PASS}"

R_UNPUB="npmunpub-${SLOT}-${SUF}"     # hosted npm, no peer: the #4025 legs
R_NSYNC="npmsync-${SLOT}-${SUF}"      # hosted npm, push-subscribed
R_GO="gosync-${SLOT}-${SUF}"          # hosted go, push-subscribed
R_GEN="gensync-${SLOT}-${SUF}"        # hosted generic, unversioned, push-subscribed
R_VER="genver-${SLOT}-${SUF}"         # hosted generic, versioned, push-subscribed

PLAIN="dtfplain"            # unscoped, 1.0.0 + 1.1.0 (version unpublish)
SCOPED="@dtfu/scoped"       # scoped,   1.0.0 + 1.1.0 (version unpublish)
WHOLE="dtfwhole"            # unscoped, 1.0.0 + 1.1.0 (whole-package unpublish)
WHOLES="@dtfu/whole"        # scoped,   1.0.0 + 1.1.0 (whole-package unpublish)
RAW="dtfraw"                # unscoped, 1.0.0..1.2.0 (raw -rev routes)
RAWS="@dtfu/raw"            # scoped,   1.0.0 + 1.1.0 (raw scoped -rev routes)
SYNCPKG="dtfsync"           # published into the push-subscribed npm repo
GOMOD="example.com/dtfsync"

WORK="$(mktemp -d -t dtf-npmunpub-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers -----------------------------------------------------------------
psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }

# Run a script inside the npm client container (stdin), echo its output.
npm_sh() { docker exec -i "$NPM_CTR" bash -s 2>&1; }

# HTTP code of a request; the body goes to $WORK/last.
code() { curl -s --path-as-is -o "$WORK/last" -w '%{http_code}' --max-time 60 "$@" 2>/dev/null || echo 000; }

repo_create() { # key format [versioning_enabled]
  local body
  body="$(jq -nc --arg k "$1" --arg f "$2" --argjson v "${3:-false}" \
    '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false,versioning_enabled:$v}')"
  curl -sf --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "$body" "${BASE_URL}/api/v1/repositories" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
}

packument() { curl -s --max-time 60 -u "$AUTH" "${BASE_URL}/npm/$1/$2" 2>/dev/null || true; }
versions_of() { packument "$1" "$2" | jq -c '[.versions // {} | keys[]] | sort' 2>/dev/null || echo '?'; }
latest_of() { packument "$1" "$2" | jq -r '."dist-tags".latest // empty' 2>/dev/null || true; }
pkg_code() { code -u "$AUTH" "${BASE_URL}/npm/$1/$2"; }
tgz_name() { local n="${1##*/}"; echo "${n}-$2.tgz"; }
tarball_code() { code -u "$AUTH" "${BASE_URL}/npm/$1/$2/-/$(tgz_name "$2" "$3")"; }
live_rows() { # repo name [version]
  local vclause=""; [ -n "${3:-}" ] && vclause="AND a.version = '$3'"
  psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
          WHERE r.key = '$1' AND a.name = '$2' AND a.is_deleted = false ${vclause}"
}
# "<status>|<retry_count>|<rows>" of the push row(s) for one artifact path.
push_state() { # repo path
  psql_q "SELECT coalesce(max(st.status::text),'none') || '|' || coalesce(max(st.retry_count),-1) || '|' || count(st.id) \
          FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
          LEFT JOIN sync_tasks st ON st.artifact_id = a.id AND st.task_type = 'push' AND st.peer_instance_id = '${PEER_ID}' \
          WHERE r.key = '$1' AND a.path = '$2' AND a.is_deleted = false"
}
mark_push_completed() { # repo path: simulate a delivered push
  psql_q "UPDATE sync_tasks st SET status = 'completed', completed_at = NOW() - INTERVAL '1 minute', retry_count = 2 \
          FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
          WHERE st.artifact_id = a.id AND st.task_type = 'push' AND st.peer_instance_id = '${PEER_ID}' \
            AND r.key = '$1' AND a.path = '$2' RETURNING st.id" | head -1
}

# .npmrc for a repo, written into the container dir $2.
npmrc_for() {
  local b64; b64="$(printf '%s' "$AUTH" | base64 -w0)"
  cat <<EOF
mkdir -p '$2' && cat > '$2/.npmrc' <<'RC'
registry=http://backend:8080/npm/$1/
@dtfu:registry=http://backend:8080/npm/$1/
//backend:8080/npm/$1/:_auth=${b64}
//backend:8080/npm/$1/:always-auth=true
RC
EOF
}

# npm publish NAME VERSION into REPO with the real client; prints npm output,
# returns npm's exit code.
npm_publish() { # repo name version
  local d="/tmp/pub-${SUF}"
  { npmrc_for "$1" "$d"
    cat <<EOF
cd '$d' && rm -rf p && mkdir p && cp .npmrc p/ && cd p
printf '{"name":"%s","version":"%s","license":"MIT","files":["index.js"]}' '$2' '$3' > package.json
printf 'module.exports = "%s@%s";\n' '$2' '$3' > index.js
npm publish --registry 'http://backend:8080/npm/$1/' --no-audit --no-fund 2>&1
EOF
  } | npm_sh
}

# npm unpublish SPEC from REPO; prints output then "rc=<n>".
npm_unpublish() { # repo spec
  local d="/tmp/unpub-${SUF}"
  { npmrc_for "$1" "$d"
    echo "cd '$d' && npm unpublish '$2' --force --registry 'http://backend:8080/npm/$1/' --loglevel http 2>&1; echo rc=\$?"
  } | npm_sh
}

# npm install SPEC from REPO into a fresh dir with a fresh cache; 0 on success.
npm_install() { # repo spec
  local d="/tmp/inst-${SUF}-$RANDOM"
  { npmrc_for "$1" "$d"
    cat <<EOF
cd '$d' && printf '{"name":"c","version":"0.0.0","private":true}' > package.json
npm install '$2' --registry 'http://backend:8080/npm/$1/' --cache '$d/cache' --no-audit --no-fund --no-package-lock 2>&1
EOF
  } | npm_sh
}

begin_suite "npm-unpublish-and-push-sync"
auth_admin

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: npm client container, repositories, push peer"
SETUP_ERR=""
docker exec "$NPM_CTR" npm --version >/dev/null 2>&1 || SETUP_ERR="npm missing in ${NPM_CTR}"
declare -A RID=()
for spec in "$R_UNPUB:npm:false" "$R_NSYNC:npm:false" "$R_GO:go:false" "$R_GEN:generic:false" "$R_VER:generic:true"; do
  IFS=: read -r k f v <<<"$spec"
  RID[$k]="$(repo_create "$k" "$f" "$v")"
  [ -n "${RID[$k]}" ] || SETUP_ERR="${SETUP_ERR} create repo ${k} failed;"
done
PEER_HOST="dtf-peer-${SLOT}-${SUF}.invalid"
PEER_ID="$(curl -sf --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"dtf-peer-${SLOT}-${SUF}\",\"endpoint_url\":\"http://${PEER_HOST}:8080\",\"api_key\":\"dtf-${SUF}\"}" \
  "${BASE_URL}/api/v1/peers" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true)"
if [ -z "$PEER_ID" ]; then
  SETUP_ERR="${SETUP_ERR} peer registration failed;"
else
  psql_q "UPDATE peer_instances SET status = 'online', last_heartbeat_at = NOW(), \
          backoff_until = NOW() + INTERVAL '1 day' WHERE id = '${PEER_ID}'" >/dev/null
  for k in "$R_NSYNC" "$R_GO" "$R_GEN" "$R_VER"; do
    c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
      -d "{\"repository_id\":\"${RID[$k]:-x}\",\"sync_enabled\":true,\"replication_mode\":\"push\"}" \
      "${BASE_URL}/api/v1/peers/${PEER_ID}/repositories")"
    [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} assign ${k} -> ${c};"
  done
fi
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

# =============================================================================
# #4025 — npm unpublish
# =============================================================================
begin_test "CONTROL: real npm publishes two versions each of 3 unscoped and 3 scoped packages"
PUB_ERR=""
for p in "$PLAIN" "$SCOPED" "$WHOLE" "$WHOLES" "$RAW" "$RAWS"; do
  for v in 1.0.0 1.1.0; do
    out="$(npm_publish "$R_UNPUB" "$p" "$v")" || PUB_ERR="${PUB_ERR} ${p}@${v}: $(tail -3 <<<"$out" | tr '\n' ' ');"
  done
done
out="$(npm_publish "$R_UNPUB" "$RAW" 1.2.0)" || PUB_ERR="${PUB_ERR} ${RAW}@1.2.0;"
v_plain="$(versions_of "$R_UNPUB" "$PLAIN")"; v_scoped="$(versions_of "$R_UNPUB" "$SCOPED")"
if [ -z "$PUB_ERR" ] && [ "$v_plain" = '["1.0.0","1.1.0"]' ] && [ "$v_scoped" = '["1.0.0","1.1.0"]' ]; then pass; else
  infra_fail "npm publish precondition failed: ${PUB_ERR} plain=${v_plain} scoped=${v_scoped}"; end_suite; exit $?
fi

begin_test "CONTROL: real npm install ${PLAIN}@1.1.0 round-trips from the registry"
rc=0; out="$(npm_install "$R_UNPUB" "${PLAIN}@1.1.0")" || rc=$?
if [ "$rc" = "0" ]; then pass; else fail "npm install ${PLAIN}@1.1.0 failed (rc=${rc})" "$(tail -5 <<<"$out")"; fi

# ---- version unpublish via the real client ----------------------------------
for pkg in "$PLAIN" "$SCOPED"; do
  out="$(npm_unpublish "$R_UNPUB" "${pkg}@1.1.0")"
  echo "  npm unpublish ${pkg}@1.1.0: $(grep -E '^npm http fetch (PUT|DELETE)|^rc=' <<<"$out" | tr '\n' ' ')"

  begin_test "FIX(#4025): after 'npm unpublish ${pkg}@1.1.0 --force' the packument no longer lists 1.1.0"
  got="$(versions_of "$R_UNPUB" "$pkg")"
  if [ "$got" = '["1.0.0"]' ]; then pass; else
    fail "the unpublished version is still served: versions=${got}, expected [\"1.0.0\"] (npm reported: $(grep '^rc=' <<<"$out"))" "$(grep -E '^npm http' <<<"$out")"
  fi

  begin_test "FIX(#4025): dist-tags.latest of ${pkg} is recomputed to 1.0.0"
  got="$(latest_of "$R_UNPUB" "$pkg")"
  if [ "$got" = "1.0.0" ]; then pass; else fail "dist-tags.latest=${got}, expected 1.0.0"; fi

  begin_test "FIX(#4025): the 1.1.0 tarball of ${pkg} answers 404"
  got="$(tarball_code "$R_UNPUB" "$pkg" 1.1.0)"
  if [ "$got" = "404" ]; then pass; else fail "tarball GET -> ${got}, expected 404 (the unpublished bytes are still downloadable)"; fi

  begin_test "FIX(#4025): no live artifacts row for ${pkg}@1.1.0, and an ARTIFACT_DELETED audit entry exists"
  rows="$(live_rows "$R_UNPUB" "$pkg" 1.1.0)"
  aud="$(psql_q "SELECT count(*) FROM audit_log WHERE action = 'ARTIFACT_DELETED' \
                 AND details->>'name' = '${pkg}' AND details->>'version' = '1.1.0' \
                 AND details->>'repository_id' = '${RID[$R_UNPUB]}'")"
  if [ "$rows" = "0" ] && [ "${aud:-0}" -ge 1 ] 2>/dev/null; then pass; else
    fail "live rows=${rows} (want 0), ARTIFACT_DELETED audit rows=${aud} (want >=1)"
  fi

  begin_test "CONTROL: ${pkg}@1.0.0 still installs with the real client after the unpublish"
  rc=0; out="$(npm_install "$R_UNPUB" "${pkg}@1.0.0")" || rc=$?
  if [ "$rc" = "0" ]; then pass; else fail "npm install ${pkg}@1.0.0 failed (rc=${rc})" "$(tail -5 <<<"$out")"; fi
done

# ---- whole-package unpublish via the real client ----------------------------
for pkg in "$WHOLE" "$WHOLES"; do
  out="$(npm_unpublish "$R_UNPUB" "$pkg")"
  echo "  npm unpublish ${pkg}: $(grep -E '^npm http fetch (PUT|DELETE)|^rc=' <<<"$out" | tr '\n' ' ')"

  begin_test "FIX(#4025): after 'npm unpublish ${pkg} --force' the packument answers 404 and no live row remains"
  pc="$(pkg_code "$R_UNPUB" "$pkg")"; rows="$(live_rows "$R_UNPUB" "$pkg")"
  tc="$(tarball_code "$R_UNPUB" "$pkg" 1.0.0)"
  if [ "$pc" = "404" ] && [ "$tc" = "404" ] && [ "$rows" = "0" ]; then pass; else
    fail "whole-package unpublish left the package served: packument=${pc} tarball(1.0.0)=${tc} live rows=${rows} (want 404/404/0)" "$(grep -E '^npm http|^rc=' <<<"$out")"
  fi

  begin_test "FIX(#4025): 'npm install ${pkg}' now fails with the real client"
  rc=0; out="$(npm_install "$R_UNPUB" "$pkg")" || rc=$?
  if [ "$rc" != "0" ]; then pass; else fail "npm install ${pkg} still succeeds after a whole-package unpublish"; fi
done

# ---- the raw -rev routes (#4727 routes.rs) ----------------------------------
begin_test "CONTROL: anonymous DELETE /npm/{repo}/${RAW}/-rev/undefined is refused and removes nothing"
c="$(code -X DELETE "${BASE_URL}/npm/${R_UNPUB}/${RAW}/-rev/undefined")"
got="$(versions_of "$R_UNPUB" "$RAW")"
if { [ "$c" = "401" ] || [ "$c" = "404" ]; } && [ "$got" = '["1.0.0","1.1.0","1.2.0"]' ]; then pass; else
  fail "anonymous whole-package DELETE -> ${c}, versions afterwards ${got}"
fi

begin_test "FIX(#4025): DELETE /npm/{repo}/${RAW}/-/$(tgz_name "$RAW" 1.2.0)/-rev/undefined -> 200 {ok:true}, version gone, repeat -> 404"
c1="$(code -u "$AUTH" -X DELETE "${BASE_URL}/npm/${R_UNPUB}/${RAW}/-/$(tgz_name "$RAW" 1.2.0)/-rev/undefined")"
ok="$(jq -r '.ok // empty' "$WORK/last" 2>/dev/null || true)"
got="$(versions_of "$R_UNPUB" "$RAW")"
c2="$(code -u "$AUTH" -X DELETE "${BASE_URL}/npm/${R_UNPUB}/${RAW}/-/$(tgz_name "$RAW" 1.2.0)/-rev/undefined")"
if [ "$c1" = "200" ] && [ "$ok" = "true" ] && [ "$got" = '["1.0.0","1.1.0"]' ] && [ "$c2" = "404" ]; then pass; else
  fail "tarball -rev DELETE: first=${c1} ok=${ok} versions=${got} repeat=${c2} (want 200/true/[1.0.0,1.1.0]/404)"
fi

curl -s --max-time 60 -u "$AUTH" "${BASE_URL}/npm/${R_UNPUB}/${RAW}?write=true" -o "$WORK/raw-write.json" 2>/dev/null || true
begin_test "FIX(#4025): PUT /npm/{repo}/${RAW}/-rev/undefined with a packument that removes nothing -> 400 (no silent ok)"
c="$(code -u "$AUTH" -X PUT -H 'Content-Type: application/json' --data-binary "@$WORK/raw-write.json" \
  "${BASE_URL}/npm/${R_UNPUB}/${RAW}/-rev/undefined")"
got="$(versions_of "$R_UNPUB" "$RAW")"
if [ "$c" = "400" ] && [ "$got" = '["1.0.0","1.1.0"]' ]; then pass; else
  fail "no-op packument PUT -> ${c} (want 400), versions=${got}" "$(head -c 300 "$WORK/last")"
fi

begin_test "FIX(#4025): PUT /npm/{repo}/${RAW}/-rev/undefined with the packument minus 1.1.0 -> 200, 1.1.0 gone"
jq 'del(.versions["1.1.0"])' "$WORK/raw-write.json" > "$WORK/raw-minus.json" 2>/dev/null || true
c="$(code -u "$AUTH" -X PUT -H 'Content-Type: application/json' --data-binary "@$WORK/raw-minus.json" \
  "${BASE_URL}/npm/${R_UNPUB}/${RAW}/-rev/undefined")"
got="$(versions_of "$R_UNPUB" "$RAW")"; rows="$(live_rows "$R_UNPUB" "$RAW" 1.1.0)"
if [ "$c" = "200" ] && [ "$got" = '["1.0.0"]' ] && [ "$rows" = "0" ]; then pass; else
  fail "packument-rewrite PUT -> ${c}, versions=${got}, live 1.1.0 rows=${rows} (want 200/[1.0.0]/0)" "$(head -c 300 "$WORK/last")"
fi

begin_test "FIX(#4025): DELETE /npm/{repo}/${RAW}/-rev/undefined -> 200, packument 404, repeat -> 404"
c1="$(code -u "$AUTH" -X DELETE "${BASE_URL}/npm/${R_UNPUB}/${RAW}/-rev/undefined")"
pc="$(pkg_code "$R_UNPUB" "$RAW")"
c2="$(code -u "$AUTH" -X DELETE "${BASE_URL}/npm/${R_UNPUB}/${RAW}/-rev/undefined")"
if [ "$c1" = "200" ] && [ "$pc" = "404" ] && [ "$c2" = "404" ]; then pass; else
  fail "whole-package -rev DELETE: first=${c1} packument=${pc} repeat=${c2} (want 200/404/404)"
fi

begin_test "FIX(#4025): scoped tarball DELETE /npm/{repo}/${RAWS}/-/$(tgz_name "$RAWS" 1.1.0)/-rev/undefined -> 200, version gone"
c="$(code -u "$AUTH" -X DELETE "${BASE_URL}/npm/${R_UNPUB}/${RAWS}/-/$(tgz_name "$RAWS" 1.1.0)/-rev/undefined")"
got="$(versions_of "$R_UNPUB" "$RAWS")"
if [ "$c" = "200" ] && [ "$got" = '["1.0.0"]' ]; then pass; else
  fail "scoped tarball -rev DELETE -> ${c}, versions=${got} (want 200/[1.0.0])"
fi

begin_test "FIX(#4025): encoded scoped DELETE /npm/{repo}/@dtfu%2fraw/-rev/undefined -> 200, packument 404 (was 405)"
c="$(code -u "$AUTH" -X DELETE "${BASE_URL}/npm/${R_UNPUB}/@dtfu%2fraw/-rev/undefined")"
pc="$(pkg_code "$R_UNPUB" "$RAWS")"
if [ "$c" = "200" ] && [ "$pc" = "404" ]; then pass; else
  fail "encoded scoped whole-package DELETE -> ${c}, packument afterwards ${pc} (want 200/404)"
fi

# =============================================================================
# #4643 — push sync tasks on npm publish and Go module upload
# =============================================================================
begin_test "CONTROL: a generic upload to a push-subscribed repo queues a pending push row (peer wiring works)"
c="$(code -u "$AUTH" -X PUT --data-binary "ctl-${SUF}" "${BASE_URL}/api/v1/repositories/${R_GEN}/artifacts/ctl/ctl.bin")"
st="$(push_state "$R_GEN" ctl/ctl.bin)"
if [ "$c" = "201" ] && [ "$st" = "pending|0|1" ]; then pass; else
  fail "generic upload -> ${c}, push row ${st} (want 201, pending|0|1)"
fi

begin_test "FIX(#4643): real 'npm publish ${SYNCPKG}@1.0.0' into a push-subscribed repo queues a pending push row"
rc=0; out="$(npm_publish "$R_NSYNC" "$SYNCPKG" 1.0.0)" || rc=$?
st="$(push_state "$R_NSYNC" "${SYNCPKG}/1.0.0/$(tgz_name "$SYNCPKG" 1.0.0)")"
if [ "$rc" = "0" ] && [ "$st" = "pending|0|1" ]; then pass; else
  fail "npm publish rc=${rc}; push row for the tarball: ${st} (want pending|0|1)" "$(tail -3 <<<"$out")"
fi

printf 'module %s\n\ngo 1.21\n' "$GOMOD" > "$WORK/go.mod"
mkdir -p "$WORK/zip/${GOMOD}@v1.0.0" && cp "$WORK/go.mod" "$WORK/zip/${GOMOD}@v1.0.0/go.mod"
(cd "$WORK/zip" && python3 -I -c "import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],'w'); z.write(sys.argv[2]); z.close()" \
  "$WORK/mod.zip" "${GOMOD}@v1.0.0/go.mod") 2>/dev/null || true

begin_test "FIX(#4643): Go .mod upload to a push-subscribed repo queues a pending push row"
c="$(code -u "$AUTH" -X PUT --data-binary "@$WORK/go.mod" "${BASE_URL}/go/${R_GO}/${GOMOD}/@v/v1.0.0.mod")"
st="$(push_state "$R_GO" "${GOMOD}/v1.0.0/go.mod")"
if [ "$c" = "201" ] && [ "$st" = "pending|0|1" ]; then pass; else
  fail "go .mod PUT -> ${c}, push row ${st} (want 201, pending|0|1)"
fi

begin_test "FIX(#4643): Go .zip upload to a push-subscribed repo queues a pending push row"
c="$(code -u "$AUTH" -X PUT -H 'Content-Type: application/zip' --data-binary "@$WORK/mod.zip" \
  "${BASE_URL}/go/${R_GO}/${GOMOD}/@v/v1.0.0.zip")"
st="$(push_state "$R_GO" "${GOMOD}/v1.0.0/v1.0.0.zip")"
if [ "$c" = "201" ] && [ "$st" = "pending|0|1" ]; then pass; else
  fail "go .zip PUT -> ${c}, push row ${st} (want 201, pending|0|1)"
fi

begin_test "CONTROL: a replication-tagged Go upload (X-Artifact-Keeper-Replication) is stored but queues nothing"
c="$(code -u "$AUTH" -X PUT -H 'X-Artifact-Keeper-Replication: true' --data-binary "@$WORK/go.mod" \
  "${BASE_URL}/go/${R_GO}/${GOMOD}/@v/v1.1.0.mod")"
st="$(push_state "$R_GO" "${GOMOD}/v1.1.0/go.mod")"
if [ "$c" = "201" ] && [ "$st" = "none|-1|0" ]; then pass; else
  fail "replicated go .mod PUT -> ${c}, push row ${st} (want 201, none|-1|0: a replicated write must not echo back)"
fi

# =============================================================================
# #4658 — a same-path re-upload re-arms the completed push row
# =============================================================================
VP="models/m.bin"
begin_test "CONTROL: first upload to a versioned generic repo queues a pending push row"
c="$(code -u "$AUTH" -X PUT --data-binary "rev1-${SUF}" "${BASE_URL}/api/v1/repositories/${R_VER}/artifacts/${VP}")"
st="$(push_state "$R_VER" "$VP")"
if [ "$c" = "201" ] && [ "$st" = "pending|0|1" ]; then pass; else
  fail "versioned first upload -> ${c}, push row ${st} (want 201, pending|0|1)"
fi
T_VER="$(mark_push_completed "$R_VER" "$VP")"

begin_test "FIX(#4658): re-upload of different bytes to the same versioned path re-arms that push row (completed -> pending, retry 0)"
c="$(code -u "$AUTH" -X PUT --data-binary "rev2-${SUF}" "${BASE_URL}/api/v1/repositories/${R_VER}/artifacts/${VP}")"
rev="$(jq -r '.revision // empty' "$WORK/last" 2>/dev/null || true)"
st="$(push_state "$R_VER" "$VP")"
same="$(psql_q "SELECT count(*) FROM sync_tasks WHERE id = '${T_VER:-00000000-0000-0000-0000-000000000000}' AND status = 'pending'")"
if [ -n "$T_VER" ] && [ "$c" = "201" ] && [ "$st" = "pending|0|1" ] && [ "$same" = "1" ]; then pass; else
  fail "versioned re-upload -> ${c} (revision ${rev}); push row ${st} (want pending|0|1, the same row ${T_VER} re-armed). The peer would keep the first revision."
fi

GP="plain/p.bin"
begin_test "CONTROL: an unversioned live overwrite is 409 and leaves the completed push row completed"
c0="$(code -u "$AUTH" -X PUT --data-binary "one-${SUF}" "${BASE_URL}/api/v1/repositories/${R_GEN}/artifacts/${GP}")"
T_GEN="$(mark_push_completed "$R_GEN" "$GP")"
c="$(code -u "$AUTH" -X PUT --data-binary "two-${SUF}" "${BASE_URL}/api/v1/repositories/${R_GEN}/artifacts/${GP}")"
st="$(push_state "$R_GEN" "$GP")"
if [ "$c0" = "201" ] && [ -n "$T_GEN" ] && [ "$c" = "409" ] && [ "$st" = "completed|2|1" ]; then pass; else
  fail "first=${c0} overwrite=${c} (want 201/409); push row ${st} (want completed|2|1)"
fi

begin_test "CONTROL: deleting it queues a pending delete row for the online peer"
c="$(code -u "$AUTH" -X DELETE "${BASE_URL}/api/v1/repositories/${R_GEN}/artifacts/${GP}")"
del="$(psql_q "SELECT st.status FROM sync_tasks st JOIN artifacts a ON a.id = st.artifact_id \
               JOIN repositories r ON r.id = a.repository_id \
               WHERE r.key = '${R_GEN}' AND a.path = '${GP}' AND st.task_type = 'delete' AND st.peer_instance_id = '${PEER_ID}'")"
if { [ "$c" = "200" ] || [ "$c" = "204" ]; } && [ "$del" = "pending" ]; then pass; else
  fail "DELETE -> ${c}, delete row status '${del}' (want 2xx, pending)"
fi

begin_test "FIX(#4658): re-upload after the delete re-arms the completed push row (completed -> pending, retry 0)"
c="$(code -u "$AUTH" -X PUT --data-binary "three-${SUF}" "${BASE_URL}/api/v1/repositories/${R_GEN}/artifacts/${GP}")"
st="$(push_state "$R_GEN" "$GP")"
if [ "$c" = "201" ] && [ "$st" = "pending|0|1" ]; then pass; else
  fail "upload after delete -> ${c}; push row ${st} (want 201, pending|0|1). The peer would stay at 404 for this path."
fi

end_suite
