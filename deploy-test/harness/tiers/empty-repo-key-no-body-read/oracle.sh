#!/usr/bin/env bash
# =============================================================================
# tiers/empty-repo-key-no-body-read/oracle.sh — an empty repository key is
#            answered in the middleware, unread (artifact-keeper#3509 / #3444)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the
# assertion + JUnit harness, then drive the real HTTP flow against the backend.
#
# THE BUG. #3444's empty-repository-key branch inserted an anonymous
# `Option<AuthExtension>` and ran the handler. That early return skips the rest
# of the middleware, including the #508 anonymous-write gate 129 lines below, so
# the handler's body extractor buffered the ENTIRE request before the in-handler
# `require_auth` could answer 401. No credential, no repository, no config: an
# unauthenticated memory-exhaustion primitive bounded only by MAX_UPLOAD_SIZE
# (10 GiB) x GLOBAL_MAX_CONCURRENCY (512). #3509 answers the existence-hiding
# 404 in the middleware instead, so nothing reads the body.
#
# THE INSTRUMENT. `curl -w '%{size_upload}'`. curl sends `Expect: 100-continue`
# for a body this size, so a backend that answers before polling the body leaves
# size_upload at exactly 0 and one that polls it uploads all of it. "0 bytes"
# alone is unfalsifiable, so a POSITIVE CONTROL on the same run uploads the SAME
# payload, authenticated, to a real repository and requires the full byte count.
#
# Discriminating gates:
#   (CONTROL)  the instrument reports a real upload; no empty-key path answers
#              an unauthenticated 5xx (the pre-#3444 behaviour #3509 must not
#              bring back); a real conda token channel still works and a bogus
#              token there is still refused; an ordinary conda repository and a
#              non-grantee's write are unaffected.
#   (BOUNDARY) every probed empty-key prefix answers 401/404 with size_upload
#              == 0 — the probe set is exactly the prefixes measured to buffer
#              on the vulnerable image, so no gate is vacuous. RED on
#              `71052767^1`: 401 after the whole body was uploaded.
#   (BOUNDARY) a repository keyed literally `t` is authorized on its own terms:
#              anonymous 401, CREDENTIALED 200 (RED: 401 — the empty-key branch
#              discarded the credential), and public<->private flips the
#              anonymous answer.
#
# --path-as-is on EVERY curl, mandatory rather than prudent: curl normalises
# `//` by default and the empty segment IS the probe.
#
# Setup failures use infra_fail(): a tier that could not be evaluated is RED but
# is NOT a statement about the candidate (harness/lib/exit_codes.sh).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"

# The repository keyed literally `t`. LITERAL by necessity: the conda
# token-channel skip triggers on the second path segment being exactly `t`, so
# the mis-resolution only exists when a repository is actually named `t`. Each
# DTF slot owns its own Postgres, so a fixed key cannot collide across slots.
# (Same reasoning as api-alias-repo-key's `cargo`/`helm` decoys.)
CONDA_T="t"
CONDA_CH="ebk-chan-${SLOT}-${SUF}"     # an ordinary conda repo, the token channel
GEN_REPO="ebk-gen-${SLOT}-${SUF}"      # the positive control's upload target
OUTSIDER="ebk-outsider-${SLOT}-${SUF}"
OUTSIDER_PASS="Ebk_${SUF}_Aa1!"

# 32 MiB. Large enough that curl attaches `Expect: 100-continue` (so a backend
# that never polls the body transfers exactly zero bytes) and that a buffered
# read is unmistakable in the JUnit body; small enough that a required gate leg
# stays fast. The vulnerable image was measured at 33554432 on every prefix
# below.
BODY_MIB=32
BODY_BYTES=$(( BODY_MIB * 1024 * 1024 ))

WORK="$(mktemp -d -t dtf-ebk-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
BODY="${WORK}/payload.bin"

# --- curl helpers -----------------------------------------------------------
CURL_RAW="--path-as-is"

# probe METHOD URL SHAPE [curl args...] -> prints "<code> <size_upload>"
#   SHAPE=raw   : --data-binary @BODY with an octet-stream content type
#   SHAPE=form  : -F file=@BODY (multipart; a few handlers bind `Multipart`)
#   SHAPE=none  : no body at all (used by the read-side controls)
probe() {
  local method="$1" url="$2" shape="$3"; shift 3
  local args=(-s -o "${WORK}/body" -w '%{http_code} %{size_upload}')
  # shellcheck disable=SC2206  # CURL_TIMEOUT is intentionally word-split
  args+=($CURL_TIMEOUT)
  args+=($CURL_RAW -X "$method")
  case "$shape" in
    raw)  args+=(-H 'Content-Type: application/octet-stream' --data-binary "@${BODY}") ;;
    form) args+=(-F "file=@${BODY}") ;;
    none) ;;
  esac
  args+=("$@")
  curl "${args[@]}" "$url" 2>/dev/null || echo "000 0"
}
code_only() { # URL [curl args...] -> http code
  local url="$1"; shift
  curl -s -o "${WORK}/body" -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW "$@" "$url" 2>/dev/null || echo 000
}
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
# A correct refusal of an empty key: 404 (the fix's existence-hiding answer) or
# 401 (the no-repo challenge that `/conda/t/...` reaches once the key resolves
# to the real repository `t`). Anything else — 2xx, 3xx, 5xx — is not.
refused() { case "$1" in 401|404) return 0 ;; *) return 1 ;; esac; }

# --- the BOUNDARY probe table -----------------------------------------------
# METHOD|PATH|SHAPE. Exactly the prefixes measured to buffer a 32 MiB anonymous
# body on the vulnerable image, so every row here is a discriminating gate
# rather than a prefix that happens to have no body extractor. `/conda/t/upload`
# is the single-slash entry (a proxy collapsing `//` does not filter it) and it
# is the one row whose key resolves to a REAL repository on the fix; `/lfs/` is
# exempt from the global request timeout, so its arm can be drip-fed.
EMPTY_KEY_PROBES="
PUT|/npm//pkg|raw
POST|/conda/t/upload|form
PUT|/lfs//objects/deadbeef|raw
PUT|/cargo//api/v1/crates/new|raw
PUT|/api/cargo//api/v1/crates/new|raw
POST|/debian//upload|raw
POST|/rpm//upload|form
POST|/gems//api/v1/gems|raw
POST|/conda//upload|form
"

# The 5xx sweep is deliberately BROADER than the buffering set: an
# unauthenticated 500 that printed an extractor's type path is what #3443
# reported and #3444 set out to fix, and #3509 must not reintroduce it on ANY
# empty-key path, including the ones that never buffered.
NO_5XX_PROBES="
PUT|/npm//pkg|none
PUT|/maven//com/x/1.0/x-1.0.jar|none
POST|/pypi//|none
POST|/debian//upload|none
PUT|/nuget//api/v2/package|none
POST|/rpm//upload|none
PUT|/cargo//api/v1/crates/new|none
PUT|/api/cargo//api/v1/crates/new|none
POST|/gems//api/v1/gems|none
PUT|/lfs//objects/deadbeef|none
PUT|/go//x|none
POST|/helm//api/charts|none
POST|/api/helm//charts|none
PUT|/composer//api/packages|none
POST|/alpine//upload|none
POST|/conda//upload|none
POST|/conda/t/upload|none
GET|/npm//pkg|none
GET|/pypi//simple/|none
GET|/maven//|none
"

begin_suite "empty-repo-key-no-body-read-3509"

# ===========================================================================
# SETUP — every failure here is INFRA: the harness could not evaluate the tier.
# ===========================================================================
auth_admin   # sets ADMIN_TOKEN

if ! dd if=/dev/urandom of="$BODY" bs=1M count="$BODY_MIB" >/dev/null 2>&1 || \
   [ "$(wc -c < "$BODY" | tr -d ' ')" != "$BODY_BYTES" ]; then
  begin_test "setup: build the ${BODY_MIB} MiB probe payload"
  infra_fail "could not create a ${BODY_BYTES}-byte payload at ${BODY}"
  end_suite
fi

mk_repo() { # KEY FORMAT IS_PUBLIC -> http code
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW -X POST \
    "${BASE_URL}/api/v1/repositories" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"key\":\"${1}\",\"name\":\"${1}\",\"format\":\"${2}\",\"repo_type\":\"local\",\"is_public\":${3}}" \
    2>/dev/null || echo 000
}
SETUP_FAILS=""
C="$(mk_repo "$CONDA_T"  conda   false)"; is_2xx "$C" || SETUP_FAILS="${SETUP_FAILS} ${CONDA_T}=${C}"
C="$(mk_repo "$CONDA_CH" conda   false)"; is_2xx "$C" || SETUP_FAILS="${SETUP_FAILS} ${CONDA_CH}=${C}"
C="$(mk_repo "$GEN_REPO" generic false)"; is_2xx "$C" || SETUP_FAILS="${SETUP_FAILS} ${GEN_REPO}=${C}"
if [ -n "$SETUP_FAILS" ]; then
  begin_test "setup: create the conda repository keyed 't', a normal conda channel and the control target"
  infra_fail "repository creation failed:${SETUP_FAILS}"
  end_suite
fi

# The credential the conda token channel embeds in the URL. Header credentials
# take precedence, so this has to be the ONLY credential on that request.
CHANNEL_TOKEN="$(curl -s $CURL_TIMEOUT $CURL_RAW -X POST "${BASE_URL}/api/v1/auth/tokens" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
  -d "{\"name\":\"ebk-channel-${SUF}\",\"scopes\":[\"read:artifacts\",\"write:artifacts\"]}" \
  2>/dev/null | jq -r '.token // empty' 2>/dev/null || true)"
if [ -z "$CHANNEL_TOKEN" ]; then
  begin_test "setup: mint the api token the conda URL token channel carries"
  infra_fail "the token mint returned empty; the token-channel controls would be unevaluable"
  end_suite
fi

OUTSIDER_ID="$(create_test_user_with_retry "$OUTSIDER" "$OUTSIDER_PASS" "${OUTSIDER}@t.test")" || true
OUTSIDER_TOKEN=""
[ -n "$OUTSIDER_ID" ] && [ "$OUTSIDER_ID" != "null" ] && OUTSIDER_TOKEN="$(login_as "$OUTSIDER" "$OUTSIDER_PASS")"
if [ -z "$OUTSIDER_TOKEN" ]; then
  begin_test "setup: create and log in a non-admin holding no grant anywhere"
  infra_fail "could not create/log in ${OUTSIDER}"
  end_suite
fi

# ===========================================================================
# (CONTROL) THE INSTRUMENT. Without this, every `size_upload == 0` below is
# unfalsifiable: a broken measurement reads 0 on both images.
# ===========================================================================
begin_test "CONTROL(instrument): an AUTHENTICATED upload of the same payload reports a NON-ZERO size_upload"
read -r CC UP <<<"$(probe PUT "${BASE_URL}/api/v1/repositories/${GEN_REPO}/artifacts/ebk/payload.bin" raw \
  -H "Authorization: Bearer ${ADMIN_TOKEN}")"
if is_2xx "$CC" && [ "$UP" = "$BODY_BYTES" ]; then pass; else
  fail "the positive control uploaded ${UP} of ${BODY_BYTES} bytes (code=${CC}); the curl size_upload instrument is not measuring a real upload, so every 'size_upload == 0' assertion below would be vacuous and this tier certifies nothing" \
    "code=${CC} size_upload=${UP} expected=${BODY_BYTES} repo=${GEN_REPO}"
fi

# ===========================================================================
# (BOUNDARY) — RED on the pre-fix baseline `71052767^1`, GREEN on the fix.
# An anonymous request whose repository-key segment is empty must be ANSWERED,
# not run: refused 401/404 with the body never read.
# ===========================================================================
while IFS='|' read -r METHOD P SHAPE; do
  [ -z "${METHOD:-}" ] && continue
  begin_test "BOUNDARY: anonymous ${METHOD} ${P} -> refused with size_upload == 0 (body never read)"
  read -r CC UP <<<"$(probe "$METHOD" "${BASE_URL}${P}" "$SHAPE")"
  if refused "$CC" && [ "${UP:-0}" = "0" ]; then
    pass
  else
    fail "UNAUTHENTICATED BODY BUFFERING (#3509): anonymous ${METHOD} ${P} answered ${CC} after accepting ${UP} bytes (expected 401/404 with 0). The empty-key branch handed the request to the format handler, whose body extractor buffered the whole upload before the in-handler auth check could refuse it — a memory-exhaustion primitive with no credential, no repository and no configuration, bounded per request only by MAX_UPLOAD_SIZE (10 GiB default) and concurrently by GLOBAL_MAX_CONCURRENCY (512)" \
      "code=${CC} size_upload=${UP} expected_upload=0 payload=${BODY_BYTES} path=${P} method=${METHOD} shape=${SHAPE}"
  fi
done <<< "$EMPTY_KEY_PROBES"

# ===========================================================================
# (CONTROL) No unauthenticated 5xx on ANY empty-key path. This is the
# pre-#3444 behaviour (axum answered a missing extension with a 500 that
# printed the extension's type path) that #3444 removed and #3509 must not
# bring back. Holds on BOTH images.
# ===========================================================================
begin_test "CONTROL: no empty-key path answers an unauthenticated 5xx (#3443's 500 stays closed)"
FIVE_XX=""
while IFS='|' read -r METHOD P SHAPE; do
  [ -z "${METHOD:-}" ] && continue
  read -r CC _ <<<"$(probe "$METHOD" "${BASE_URL}${P}" "$SHAPE")"
  case "$CC" in 5??|000) FIVE_XX="${FIVE_XX} ${METHOD}:${P}=${CC}" ;; esac
done <<< "$NO_5XX_PROBES"
if [ -z "$FIVE_XX" ]; then pass; else
  fail "an anonymous request with an empty repository-key segment produced a 5xx:${FIVE_XX}. #3443 reported exactly this — axum answers a missing Extension with a 500 whose body prints the extension's type path — and #3509 closes it by never invoking the handler" \
    "offenders:${FIVE_XX}"
fi

# ===========================================================================
# (BOUNDARY + CONTROL) A repository whose key is literally `t`.
# `extract_repo_key` skipped the conda `t/<TOKEN>` pair on ANY conda path whose
# second segment was `t`, including the two-segment plain routes, so this
# repository resolved to an EMPTY key: no visibility, token-scope or permission
# check, and the caller's credential replaced with the anonymous value.
# ===========================================================================
begin_test "CONTROL: anonymous GET /conda/t/channeldata.json on the PRIVATE repository keyed 't' -> 401"
CC="$(code_only "${BASE_URL}/conda/${CONDA_T}/channeldata.json")"
if [ "$CC" = "401" ]; then pass; else
  fail "an anonymous read of the private repository keyed '${CONDA_T}' returned ${CC}, expected 401" "code=${CC}"
fi

begin_test "BOUNDARY: a CREDENTIALED GET /conda/t/channeldata.json -> 200 (baseline: 401, the credential was discarded)"
CC="$(code_only "${BASE_URL}/conda/${CONDA_T}/channeldata.json" -H "Authorization: Bearer ${ADMIN_TOKEN}")"
if [ "$CC" = "200" ]; then pass; else
  fail "EMPTY-KEY MIS-RESOLUTION (#3509): a valid credential reading its own private conda channel at /conda/${CONDA_T}/channeldata.json got ${CC}, expected 200. '/conda/t/<route>' is the PLAIN conda router serving a repository keyed '${CONDA_T}', not a token channel; skipping the 't/<TOKEN>' pair resolved it to an empty key, and the empty-key branch replaced the caller's credential with the anonymous value" \
    "code=${CC} repo=${CONDA_T}"
fi

begin_test "CONTROL: flipping the repository keyed 't' public<->private flips the anonymous answer"
flip_repo() { # IS_PUBLIC -> http code of the PATCH
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW -X PATCH \
    "${BASE_URL}/api/v1/repositories/${CONDA_T}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"is_public\":${1}}" 2>/dev/null || echo 000
}
# The middleware keeps a short-lived repository cache, so poll for the flip
# rather than assuming it is visible on the very next request.
await_anon() { # EXPECTED_CODE -> the code finally observed
  local want="$1" i c=""
  for i in $(seq 1 10); do
    c="$(code_only "${BASE_URL}/conda/${CONDA_T}/channeldata.json")"
    [ "$c" = "$want" ] && break
    sleep 1
  done
  echo "$c"
}
PUB_PATCH="$(flip_repo true)";  PUB_ANON="$(await_anon 200)"
PRIV_PATCH="$(flip_repo false)"; PRIV_ANON="$(await_anon 401)"
if is_2xx "$PUB_PATCH" && is_2xx "$PRIV_PATCH" && [ "$PUB_ANON" = "200" ] && [ "$PRIV_ANON" = "401" ]; then
  pass
else
  fail "the visibility of the repository keyed '${CONDA_T}' does not govern its anonymous answer: public PATCH=${PUB_PATCH} anon=${PUB_ANON} (expected 200), private PATCH=${PRIV_PATCH} anon=${PRIV_ANON} (expected 401). A key that is authorized properly must respond to its own visibility setting" \
    "public_patch=${PUB_PATCH} public_anon=${PUB_ANON} private_patch=${PRIV_PATCH} private_anon=${PRIV_ANON}"
fi

begin_test "CONTROL: a non-admin with NO grant on 't' is still refused a write to it"
read -r CC UP <<<"$(probe POST "${BASE_URL}/conda/${CONDA_T}/upload" form \
  -H "Authorization: Bearer ${OUTSIDER_TOKEN}")"
if [ "$CC" = "401" ] || [ "$CC" = "403" ]; then pass; else
  fail "a non-admin holding no grant on the private repository keyed '${CONDA_T}' got ${CC} on POST /conda/${CONDA_T}/upload (expected 401/403). Resolving the key correctly must not also confer a write" \
    "code=${CC} size_upload=${UP} user=${OUTSIDER}"
fi

# ===========================================================================
# (CONTROL) The real conda token channel — `/conda/t/<TOKEN>/<repo>/...`, where
# a segment DOES follow the token — must keep working, and a bogus token there
# must still be refused. #3509 narrows the skip; it must not remove it.
# ===========================================================================
begin_test "CONTROL: the conda token channel /conda/t/<TOKEN>/<repo>/channeldata.json still serves -> 200"
CC="$(code_only "${BASE_URL}/conda/t/${CHANNEL_TOKEN}/${CONDA_CH}/channeldata.json")"
if [ "$CC" = "200" ]; then pass; else
  fail "the conda URL token channel returned ${CC}, expected 200 — a valid token embedded in the path must still authenticate the private channel it names (this is the behaviour the narrowed skip has to preserve)" \
    "code=${CC} repo=${CONDA_CH}"
fi

begin_test "CONTROL: the same token channel with a BOGUS token -> 401 (the URL credential is still verified)"
CC="$(code_only "${BASE_URL}/conda/t/not-a-real-token-${SUF}/${CONDA_CH}/channeldata.json")"
if [ "$CC" = "401" ]; then pass; else
  fail "a bogus URL token on /conda/t/<TOKEN>/${CONDA_CH}/channeldata.json returned ${CC}, expected 401; the token channel must fail closed" \
    "code=${CC} repo=${CONDA_CH}"
fi

begin_test "CONTROL: an ordinary conda repository is unaffected — anonymous 401, credentialed 200"
ANON="$(code_only "${BASE_URL}/conda/${CONDA_CH}/channeldata.json")"
AUTHED="$(code_only "${BASE_URL}/conda/${CONDA_CH}/channeldata.json" -H "Authorization: Bearer ${ADMIN_TOKEN}")"
if [ "$ANON" = "401" ] && [ "$AUTHED" = "200" ]; then pass; else
  fail "a normally-keyed private conda repository answered anon=${ANON} credentialed=${AUTHED} (expected 401 and 200); authorization outcomes on non-empty keys must be unchanged by #3509" \
    "anon=${ANON} credentialed=${AUTHED} repo=${CONDA_CH}"
fi

begin_test "CONTROL: a non-empty repository key is still never read before it is authorized"
# The mirror of the boundary block: with a REAL (but unauthorized) key the body
# must not be read either. This held before #3444 and after #3509, and it is
# what makes the empty-key result a defect rather than a policy difference.
read -r CC UP <<<"$(probe PUT "${BASE_URL}/npm/${CONDA_CH}/pkg" raw)"
if refused "$CC" && [ "${UP:-0}" = "0" ]; then pass; else
  fail "an anonymous PUT to a NON-EMPTY repository key answered ${CC} after accepting ${UP} bytes (expected 401/404 with 0); the normal path must refuse before the body is read" \
    "code=${CC} size_upload=${UP} path=/npm/${CONDA_CH}/pkg"
fi

end_suite
