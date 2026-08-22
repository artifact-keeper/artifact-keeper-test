#!/usr/bin/env bash
# =============================================================================
# tiers/api-alias-repo-key/oracle.sh — /api/{cargo,helm} alias repo-key
#                                      resolution (artifact-keeper#3443/#3444)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the
# assertion + JUnit harness, then drive the real HTTP flow against the backend.
#
# THE BUG. `extract_repo_key` modelled every format route as
# `/{format}/{repo_key}/...`, but the #3392 alias mounts are
# `/api/{format}/{repo_key}/...`. The key handed to repo_visibility_middleware
# was therefore the literal "cargo"/"helm" while the handler served the real
# THIRD segment — the middleware authorized one repository and the handler
# served a different one.
#
# THE DECOY IS LOAD-BEARING. With no repo named `cargo`/`helm` the split fails
# CLOSED (the #3443 404) and this tier would pass on the vulnerable image and
# prove nothing. So setup creates a PUBLIC repository literally keyed `cargo`
# and one keyed `helm` — both are legal keys and both are the obvious name for
# such a repo — next to private victim repositories that hold real content.
#
# Discriminating gates:
#   (CONTROL)  true on BOTH images: the owner of the repo genuinely named
#              `cargo` reads and publishes through /api/cargo/cargo/...; the
#              `helm` repo still accepts a cm-push chart; the anonymous public
#              read on the decoy works; the NATIVE /cargo/{private} mount 401s;
#              /api/v1/* is untouched.
#   (BOUNDARY) anonymous private read (config.json / sparse index / crate
#              bytes), cross-repo publish, cross-repo existence leak and
#              cross-repo delete are all refused (401/403). RED on the
#              vulnerable baseline (2xx / 409). The delete gate asserts the
#              observable side effect in the DB AND in index.yaml.
#   (FIX)      #3443's compatibility half: a correctly-scoped token reaches its
#              OWN normally-named repo through the alias (RED on baseline too,
#              there because the alias failed closed).
#
# --path-as-is on EVERY curl: curl normalises dot segments by default and has
# produced false 200s while probing this exact bug.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"

# The DECOYS. These keys are LITERAL by necessity: the whole bug is that the
# middleware reads the format segment as the repository key, so the exploit
# only exists when a repository is actually named after the format. Each DTF
# slot owns its own Postgres, so a fixed key cannot collide across slots.
DECOY_CARGO="cargo"
DECOY_HELM="helm"

# The VICTIMS — private, suffixed so nothing else in the slot can collide.
VC="alias-vcargo-${SLOT}-${SUF}"     # private cargo repo with a published crate
VH="alias-vhelm-${SLOT}-${SUF}"      # private helm repo with three charts
# A normally-named repo the OWNER legitimately holds, used by the (FIX) gate.
OWN="alias-own-${SLOT}-${SUF}"

OWNER="alias-owner-${SLOT}-${SUF}"
OWNER_PASS="Alias_${SUF}_Aa1!"

VICTIM_CRATE="aliasvictimcrate"
VICTIM_CRATE_VER="0.1.0"
# Sparse-index coordinates for a >=4 character crate name: /{a}{b}/{c}{d}/{name}
IDX_P1="${VICTIM_CRATE:0:2}"
IDX_P2="${VICTIM_CRATE:2:2}"
# The crate the cross-repo publish tries to force into the victim.
POISON_CRATE="aliaspoisoncrate"
POISON_CRATE_VER="9.9.9"

VICTIM_CHART="aliasvictimchart"
VICTIM_CHART_VERS="1.0.0 1.1.0 1.2.0"
VICTIM_CHART_DELETE_VER="1.2.0"

WORK="$(mktemp -d -t dtf-alias-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- curl helpers -----------------------------------------------------------
# EVERY probe passes --path-as-is. See the header.
CURL_RAW="--path-as-is"

code_get() {   # URL [HEADER...]
  local url="$1"; shift
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW "$@" "$url" 2>/dev/null || echo 000
}
body_get() {   # URL [HEADER...]
  local url="$1"; shift
  curl -s $CURL_TIMEOUT $CURL_RAW "$@" "$url" 2>/dev/null || true
}
code_to_file() { # URL OUTFILE [HEADER...]
  local url="$1" out="$2"; shift 2
  curl -s -o "$out" -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW "$@" "$url" 2>/dev/null || echo 000
}

# refused CODE -> 0 when the backend refused the request the way the fix does.
# 401 (anonymous on a private repo), 403 (token repo-scope / permission) and
# 404 (existence-hiding) are all correct refusals; anything else is not.
refused() { case "$1" in 401|403|404) return 0 ;; *) return 1 ;; esac; }

# --- fixture builders -------------------------------------------------------
# make_crate NAME VERSION -> prints the path of a cargo publish payload
#   4B LE json length | json metadata | 4B LE crate length | .crate bytes
make_crate() {
  local name="$1" vers="$2"
  local dir="${WORK}/crate-${name}-${vers}"
  mkdir -p "${dir}/src"
  cat > "${dir}/Cargo.toml" <<EOT
[package]
name = "${name}"
version = "${vers}"
edition = "2021"
description = "DTF api-alias fixture"
license = "MIT"

[lib]
name = "${name}"
path = "src/lib.rs"
EOT
  printf 'pub fn hello() -> &%sstatic str { "%s %s" }\n' "'" "$name" "$vers" > "${dir}/src/lib.rs"
  local crate_file="${WORK}/${name}-${vers}.crate"
  tar czf "$crate_file" -C "$dir" . 2>/dev/null
  local meta payload
  meta="$(jq -nc --arg n "$name" --arg v "$vers" \
    '{name:$n,vers:$v,deps:[],features:{},authors:["dtf"],description:"DTF api-alias fixture",license:"MIT",readme:null,repository:null,links:null}')"
  payload="${WORK}/publish-${name}-${vers}.bin"
  CRATE_FILE="$crate_file" META="$meta" OUT="$payload" python3 - <<'PY' 2>/dev/null
import os, struct
meta = os.environ["META"].encode()
data = open(os.environ["CRATE_FILE"], "rb").read()
with open(os.environ["OUT"], "wb") as f:
    f.write(struct.pack("<I", len(meta))); f.write(meta)
    f.write(struct.pack("<I", len(data))); f.write(data)
PY
  echo "$payload"
}

# make_chart NAME VERSION -> prints the path of a chart .tgz
# A Helm chart package is just a gzipped tar whose entries live under
# <name>/; the backend reads only Chart.yaml, so `tar` is enough and the
# oracle needs no `helm` binary on the runner.
make_chart() {
  local name="$1" vers="$2"
  local dir="${WORK}/chart-${name}-${vers}/${name}"
  mkdir -p "${dir}/templates"
  cat > "${dir}/Chart.yaml" <<EOT
apiVersion: v2
name: ${name}
description: DTF api-alias fixture chart
type: application
version: ${vers}
appVersion: "1.0.0"
EOT
  printf 'replicaCount: 1\n' > "${dir}/values.yaml"
  printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s-cfg\n' "$name" \
    > "${dir}/templates/configmap.yaml"
  local out="${WORK}/${name}-${vers}.tgz"
  tar czf "$out" -C "${WORK}/chart-${name}-${vers}" "$name" 2>/dev/null
  echo "$out"
}

# --- DB / index observers ---------------------------------------------------
live_artifacts() { # REPO_KEY -> count of non-deleted artifact rows
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
    SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id
    WHERE r.key = '${1}' AND a.is_deleted = false;" 2>/dev/null | tr -d '[:space:]' || echo "?"
}
crate_rows() { # REPO_KEY CRATE_NAME -> count of non-deleted rows for that crate
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
    SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id
    WHERE r.key = '${1}' AND a.name = '${2}' AND a.is_deleted = false;" 2>/dev/null | tr -d '[:space:]' || echo "?"
}
index_entries() { # REPO_KEY BEARER -> number of `- version:` entries in index.yaml
  body_get "${BASE_URL}/helm/${1}/index.yaml" -H "Authorization: Bearer ${2}" \
    | grep -c '^[[:space:]]*-\{0,1\}[[:space:]]*version:' 2>/dev/null || echo 0
}

begin_suite "api-alias-repo-key-authz"

# ===========================================================================
# SETUP
# ===========================================================================
auth_admin   # sets ADMIN_TOKEN

OWNER_ID="$(create_test_user_with_retry "$OWNER" "$OWNER_PASS" "${OWNER}@t.test")" || true
if [ -z "$OWNER_ID" ] || [ "$OWNER_ID" = "null" ]; then
  begin_test "setup: create the decoy-repo owner"
  infra_fail "could not create user ${OWNER}"
  end_suite
fi

OWNER_TOKEN="$(login_as "$OWNER" "$OWNER_PASS")" || true
if [ -z "$OWNER_TOKEN" ]; then
  begin_test "setup: log in the decoy-repo owner"
  infra_fail "could not log in as ${OWNER}"
  end_suite
fi

# The DECOY repositories: PUBLIC, keyed exactly after the format name. This is
# the precondition that turns the middleware/handler disagreement from
# fail-closed (#3443) into a live authorization bypass. Without it the tier
# would be GREEN on the vulnerable image.
mk_repo() { # KEY FORMAT IS_PUBLIC
  api_post "/api/v1/repositories" \
    "{\"key\":\"${1}\",\"name\":\"${1}\",\"format\":\"${2}\",\"repo_type\":\"local\",\"is_public\":${3}}" \
    >/dev/null 2>&1
}
SETUP_FAILS=""
mk_repo "$DECOY_CARGO" cargo true  || SETUP_FAILS="${SETUP_FAILS} ${DECOY_CARGO}"
mk_repo "$DECOY_HELM"  helm  true  || SETUP_FAILS="${SETUP_FAILS} ${DECOY_HELM}"
mk_repo "$VC"          cargo false || SETUP_FAILS="${SETUP_FAILS} ${VC}"
mk_repo "$VH"          helm  false || SETUP_FAILS="${SETUP_FAILS} ${VH}"
mk_repo "$OWN"         cargo false || SETUP_FAILS="${SETUP_FAILS} ${OWN}"
if [ -n "$SETUP_FAILS" ]; then
  begin_test "setup: create the decoy + victim repositories"
  infra_fail "could not create repositories:${SETUP_FAILS}"
  end_suite
fi

# The owner genuinely owns the two decoys and its own normally-named repo, and
# holds NOTHING on the victims. Every boundary below must therefore be decided
# by which repository the request resolves to — not by missing RBAC.
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  INSERT INTO role_assignments (user_id, role_id, repository_id)
  SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
  WHERE u.username = '${OWNER}' AND r.name = 'repository-owner'
    AND repo.key IN ('${DECOY_CARGO}','${DECOY_HELM}','${OWN}')
  ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true

GRANTS="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  SELECT count(*) FROM role_assignments ra
  JOIN users u ON u.id = ra.user_id JOIN repositories repo ON repo.id = ra.repository_id
  WHERE u.username = '${OWNER}'
    AND repo.key IN ('${DECOY_CARGO}','${DECOY_HELM}','${OWN}');" 2>/dev/null | tr -d '[:space:]' || echo 0)"
if [ "${GRANTS:-0}" -lt 3 ]; then
  begin_test "setup: grant the owner repository-owner on the decoys"
  infra_fail "expected >=3 role assignments for ${OWNER}, saw '${GRANTS}'"
  end_suite
fi

# --- seed the victim repositories with real content (as admin) --------------
VICTIM_PAYLOAD="$(make_crate "$VICTIM_CRATE" "$VICTIM_CRATE_VER")"
POISON_PAYLOAD="$(make_crate "$POISON_CRATE" "$POISON_CRATE_VER")"
if [ ! -s "$VICTIM_PAYLOAD" ] || [ ! -s "$POISON_PAYLOAD" ]; then
  begin_test "setup: build the cargo publish fixtures"
  infra_fail "could not build the cargo publish payloads (python3/jq/tar available?)"
  end_suite
fi

SEED_CRATE="$(code_to_file "${BASE_URL}/cargo/${VC}/api/v1/crates/new" /dev/null \
  -X PUT -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/octet-stream' --data-binary "@${VICTIM_PAYLOAD}")"
if [ "$SEED_CRATE" != "200" ] && [ "$SEED_CRATE" != "201" ]; then
  begin_test "setup: publish the private victim crate on the NATIVE cargo mount"
  infra_fail "seeding ${VICTIM_CRATE} into ${VC} returned ${SEED_CRATE}"
  end_suite
fi
# The exact byte length the private .crate download would return — the
# anonymous-read boundary asserts the caller never receives this many bytes.
VICTIM_CRATE_BYTES="$(wc -c < "${WORK}/${VICTIM_CRATE}-${VICTIM_CRATE_VER}.crate" | tr -d ' ')"

CHART_SEED_FAILS=""
for v in $VICTIM_CHART_VERS; do
  f="$(make_chart "$VICTIM_CHART" "$v")"
  c="$(code_to_file "${BASE_URL}/helm/${VH}/api/charts" /dev/null \
    -X POST -H "Authorization: Bearer ${ADMIN_TOKEN}" -F "chart=@${f}")"
  case "$c" in 200|201) ;; *) CHART_SEED_FAILS="${CHART_SEED_FAILS} ${v}=${c}" ;; esac
done
if [ -n "$CHART_SEED_FAILS" ]; then
  begin_test "setup: publish the private victim charts on the NATIVE helm mount"
  infra_fail "seeding charts into ${VH} failed:${CHART_SEED_FAILS}"
  end_suite
fi

# Seed the repo genuinely named `cargo` too, so the CONTROL read has content
# and cannot pass for the trivial reason that the repo is empty.
DECOY_PAYLOAD="$(make_crate "decoycrate" "0.1.0")"
code_to_file "${BASE_URL}/cargo/${DECOY_CARGO}/api/v1/crates/new" /dev/null \
  -X PUT -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/octet-stream' --data-binary "@${DECOY_PAYLOAD}" >/dev/null

# --- repo-scoped tokens ------------------------------------------------------
# `POST /api/v1/repositories/{key}/tokens` binds the token to exactly that
# repository (api_token_repositories). #504's ceiling is the control under
# test: such a token must never reach a repository it is not bound to.
#
# The read/write tokens are minted BY THE OWNER, so the cross-repo publish and
# the existence leak below are a genuine cross-tenant reach: a tenant who owns
# the repository named `cargo`/`helm` and holds nothing at all on the victims.
# `delete:artifacts` is an admin-only scope at mint time, so the destructive
# primitive uses a repo-scoped token an OPERATOR would issue for the `helm`
# repository. That token's holder is an admin, which makes the gate SHARPER,
# not weaker: repository binding is the only control left standing, it is
# enforced ahead of the admin permission shortcut, and a deploy token issued
# for one repository must not be able to destroy content in another.
mint_repo_token() { # BEARER REPO_KEY SCOPES_JSON -> prints the token
  curl -s $CURL_TIMEOUT $CURL_RAW -X POST "${BASE_URL}/api/v1/repositories/${2}/tokens" \
    -H "Authorization: Bearer ${1}" -H 'Content-Type: application/json' \
    -d "{\"name\":\"alias-${2}-${3//[^a-z]/}-${SUF}\",\"scopes\":${3}}" \
    2>/dev/null | jq -r '.token // empty' 2>/dev/null || true
}
RW='["read:artifacts","write:artifacts"]'
RD='["read:artifacts","delete:artifacts"]'
CARGO_TOKEN="$(mint_repo_token "$OWNER_TOKEN" "$DECOY_CARGO" "$RW")"
HELM_TOKEN="$(mint_repo_token "$OWNER_TOKEN" "$DECOY_HELM" "$RW")"
HELM_DEL_TOKEN="$(mint_repo_token "$ADMIN_TOKEN" "$DECOY_HELM" "$RD")"
OWN_TOKEN="$(mint_repo_token "$OWNER_TOKEN" "$OWN" "$RW")"
if [ -z "$CARGO_TOKEN" ] || [ -z "$HELM_TOKEN" ] || [ -z "$HELM_DEL_TOKEN" ] || [ -z "$OWN_TOKEN" ]; then
  begin_test "setup: mint the repo-scoped tokens on cargo / helm / the owner's repo"
  infra_fail "token mint returned empty (cargo='${CARGO_TOKEN:0:8}' helm='${HELM_TOKEN:0:8}' helmDel='${HELM_DEL_TOKEN:0:8}' own='${OWN_TOKEN:0:8}'); the tier never probed the alias" \
    "owner=${OWNER}"
  end_suite
fi

# Baselines taken BEFORE any boundary probe runs.
VH_LIVE_BEFORE="$(live_artifacts "$VH")"
VH_INDEX_BEFORE="$(index_entries "$VH" "$ADMIN_TOKEN")"
if ! [[ "$VH_LIVE_BEFORE" =~ ^[0-9]+$ ]] || [ "$VH_LIVE_BEFORE" -lt 3 ]; then
  begin_test "setup: read the victim helm repo's live artifact count"
  infra_fail "expected >=3 live artifacts in ${VH}, saw '${VH_LIVE_BEFORE}'"
  end_suite
fi

# ===========================================================================
# (CONTROL) — must hold on BOTH the vulnerable baseline and the fix.
# These are the "did the fix break anything" half. A repository legitimately
# named after a format keeps working, on the alias and natively, for anonymous
# public reads and for its own scoped token.
# ===========================================================================
begin_test "CONTROL: anonymous GET /api/cargo/cargo/config.json -> 200 (public repo named after the format still served on the alias)"
CC="$(code_get "${BASE_URL}/api/${DECOY_CARGO}/${DECOY_CARGO}/config.json")"
if [ "$CC" = "200" ]; then pass; else
  fail "the alias read of the PUBLIC repository literally named '${DECOY_CARGO}' returned ${CC}, expected 200 — legitimate use of a format-named repository regressed" "code=${CC}"
fi

begin_test "CONTROL: token scoped to repo 'cargo' GET /api/cargo/cargo/config.json -> 200 (its own repo, through the alias)"
CC="$(code_get "${BASE_URL}/api/${DECOY_CARGO}/${DECOY_CARGO}/config.json" -H "Authorization: Bearer ${CARGO_TOKEN}")"
if [ "$CC" = "200" ]; then pass; else
  fail "a token scoped to '${DECOY_CARGO}' was refused ${CC} on its OWN repository through the alias, expected 200" "code=${CC}"
fi

begin_test "CONTROL: token scoped to repo 'cargo' PUT /api/cargo/cargo/api/v1/crates/new -> 2xx (legit alias publish into its own repo)"
CTL_PAYLOAD="$(make_crate "ctlcrate" "0.2.0")"
CC="$(code_to_file "${BASE_URL}/api/${DECOY_CARGO}/${DECOY_CARGO}/api/v1/crates/new" /dev/null \
  -X PUT -H "Authorization: Bearer ${CARGO_TOKEN}" \
  -H 'Content-Type: application/octet-stream' --data-binary "@${CTL_PAYLOAD}")"
if [ "$CC" = "200" ] || [ "$CC" = "201" ]; then pass; else
  fail "the legitimate alias publish into the repository named '${DECOY_CARGO}' returned ${CC}, expected 200/201" "code=${CC}"
fi

begin_test "CONTROL: token scoped to repo 'helm' POST /api/helm/helm/charts -> 2xx (cm-push into its own repo)"
CTL_CHART="$(make_chart "ctlchart" "0.3.0")"
CC="$(code_to_file "${BASE_URL}/api/${DECOY_HELM}/${DECOY_HELM}/charts" /dev/null \
  -X POST -H "Authorization: Bearer ${HELM_TOKEN}" -F "chart=@${CTL_CHART}")"
if [ "$CC" = "200" ] || [ "$CC" = "201" ]; then pass; else
  fail "the legitimate cm-push into the repository named '${DECOY_HELM}' returned ${CC}, expected 200/201" "code=${CC}"
fi

begin_test "CONTROL: anonymous GET /cargo/{private}/config.json on the NATIVE mount -> 401 (the native route was never the problem)"
CC="$(code_get "${BASE_URL}/cargo/${VC}/config.json")"
if [ "$CC" = "401" ]; then pass; else
  fail "the NATIVE cargo mount answered ${CC} for an anonymous read of the private repo ${VC}, expected 401 — this control must hold on both images" "code=${CC}"
fi

begin_test "CONTROL: /api/v1/* is not treated as a format alias (admin GET /api/v1/repositories -> 200)"
CC="$(code_get "${BASE_URL}/api/v1/repositories" -H "Authorization: Bearer ${ADMIN_TOKEN}")"
if [ "$CC" = "200" ]; then pass; else
  fail "the REST API under /api/v1 returned ${CC}, expected 200 — a broadened /api/<x> rule would read 'v1' as a format and the resource name as a repository key" "code=${CC}"
fi

# ===========================================================================
# (BOUNDARY) — RED on the vulnerable baseline, GREEN on the fix.
# ===========================================================================
begin_test "BOUNDARY: anonymous GET /api/cargo/{private}/config.json -> refused (baseline: 200)"
CC="$(code_get "${BASE_URL}/api/${DECOY_CARGO}/${VC}/config.json")"
if refused "$CC"; then pass; else
  fail "ALIAS AUTHZ BYPASS (#3444): an anonymous GET of the PRIVATE repository ${VC} through /api/cargo/ returned ${CC}, expected 401. The middleware authorized the decoy repository '${DECOY_CARGO}' while the handler served '${VC}'." \
    "code=${CC} decoy=${DECOY_CARGO} victim=${VC}"
fi

begin_test "BOUNDARY: anonymous GET /api/cargo/{private}/{a}/{b}/{crate} sparse index -> refused (baseline: 200)"
CC="$(code_get "${BASE_URL}/api/${DECOY_CARGO}/${VC}/${IDX_P1}/${IDX_P2}/${VICTIM_CRATE}")"
if refused "$CC"; then pass; else
  fail "ALIAS AUTHZ BYPASS (#3444): the private sparse index of ${VC} was served anonymously through /api/cargo/ (${CC}), expected 401 — this enumerates every crate name and version in a private registry." \
    "code=${CC} path=/api/${DECOY_CARGO}/${VC}/${IDX_P1}/${IDX_P2}/${VICTIM_CRATE}"
fi

begin_test "BOUNDARY: anonymous GET /api/cargo/{private}/api/v1/crates/{c}/{v}/download -> refused AND no private bytes (baseline: 200 + the .crate)"
DL="${WORK}/leak.crate"
CC="$(code_to_file "${BASE_URL}/api/${DECOY_CARGO}/${VC}/api/v1/crates/${VICTIM_CRATE}/${VICTIM_CRATE_VER}/download" "$DL")"
GOT="$(wc -c < "$DL" 2>/dev/null | tr -d ' ')"; GOT="${GOT:-0}"
MAGIC="$(head -c 2 "$DL" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
if refused "$CC" && [ "$MAGIC" != "1f8b" ] && [ "$GOT" != "$VICTIM_CRATE_BYTES" ]; then
  pass
else
  fail "ALIAS AUTHZ BYPASS (#3444): an anonymous caller downloaded ${GOT} bytes of the private crate ${VICTIM_CRATE}-${VICTIM_CRATE_VER} from ${VC} through /api/cargo/ (code=${CC}, gzip-magic='${MAGIC}', private artifact is ${VICTIM_CRATE_BYTES} bytes). Expected 401 and no artifact bytes." \
    "code=${CC} bytes=${GOT} expectedPrivateBytes=${VICTIM_CRATE_BYTES} magic=${MAGIC}"
fi

begin_test "BOUNDARY: token scoped to repo 'cargo' PUT /api/cargo/{other}/api/v1/crates/new -> refused (baseline: 200, cross-repo publish)"
CC="$(code_to_file "${BASE_URL}/api/${DECOY_CARGO}/${VC}/api/v1/crates/new" /dev/null \
  -X PUT -H "Authorization: Bearer ${CARGO_TOKEN}" \
  -H 'Content-Type: application/octet-stream' --data-binary "@${POISON_PAYLOAD}")"
if refused "$CC"; then pass; else
  fail "ALIAS AUTHZ BYPASS (#3444): a token bound to repository '${DECOY_CARGO}' published ${POISON_CRATE}-${POISON_CRATE_VER} into the unrelated PRIVATE repository ${VC} through /api/cargo/ (code=${CC}), expected 403. The #504 token repo-scope ceiling was evaluated against the decoy." \
    "code=${CC} token_scope=${DECOY_CARGO} victim=${VC}"
fi

begin_test "BOUNDARY(DB): the cross-repo publish left NO artifact row in the victim (fix: 0 — baseline persists one)"
POISON_ROWS="$(crate_rows "$VC" "$POISON_CRATE")"
if [ "$POISON_ROWS" = "0" ]; then pass; else
  fail "the scope-denied cross-repo publish persisted ${POISON_ROWS} artifact row(s) for '${POISON_CRATE}' in ${VC}; a refused publish must write none" \
    "rows=${POISON_ROWS} repo=${VC} crate=${POISON_CRATE}"
fi

begin_test "BOUNDARY: token scoped to repo 'helm' POST /api/helm/{private}/charts -> refused, NOT the 409 existence leak (baseline: 409 'already exists')"
DUP_CHART="$(make_chart "$VICTIM_CHART" "$VICTIM_CHART_DELETE_VER")"
DUPBODY="${WORK}/dup.out"
CC="$(code_to_file "${BASE_URL}/api/${DECOY_HELM}/${VH}/charts" "$DUPBODY" \
  -X POST -H "Authorization: Bearer ${HELM_TOKEN}" -F "chart=@${DUP_CHART}")"
if refused "$CC"; then pass; else
  fail "ALIAS AUTHZ BYPASS (#3444): a token bound to repository '${DECOY_HELM}' reached the PRIVATE repository ${VH} through /api/helm/ and got ${CC}. A 409 here is a cross-repo EXISTENCE ORACLE — the caller learns which chart versions a private repo holds by watching upload conflicts; a 2xx is a cross-repo write. Expected 403." \
    "code=${CC} body=$(head -c 200 "$DUPBODY" 2>/dev/null) token_scope=${DECOY_HELM} victim=${VH}"
fi

begin_test "BOUNDARY: token scoped to repo 'helm' DELETE /api/helm/{private}/charts/{c}/{v} -> refused (baseline: 200 {\"deleted\":true})"
CC="$(code_get "${BASE_URL}/api/${DECOY_HELM}/${VH}/charts/${VICTIM_CHART}/${VICTIM_CHART_DELETE_VER}" \
  -X DELETE -H "Authorization: Bearer ${HELM_DEL_TOKEN}")"
if refused "$CC"; then pass; else
  fail "ALIAS AUTHZ BYPASS (#3444): a token bound to repository '${DECOY_HELM}' DELETED ${VICTIM_CHART} ${VICTIM_CHART_DELETE_VER} out of the unrelated PRIVATE repository ${VH} through /api/helm/ (code=${CC}), expected 403. This is a destructive cross-repo primitive." \
    "code=${CC} token_scope=${DECOY_HELM} victim=${VH}"
fi

begin_test "BOUNDARY(DB): the victim helm repo's live artifact count is UNCHANGED (fix) — the baseline delete drops it"
VH_LIVE_AFTER="$(live_artifacts "$VH")"
if [ "$VH_LIVE_AFTER" = "$VH_LIVE_BEFORE" ]; then pass; else
  fail "the cross-repo delete took effect: ${VH} held ${VH_LIVE_BEFORE} live artifacts before the refused DELETE and ${VH_LIVE_AFTER} after. A refused delete must not soft-delete anything." \
    "before=${VH_LIVE_BEFORE} after=${VH_LIVE_AFTER} repo=${VH}"
fi

begin_test "BOUNDARY(index): the victim's index.yaml still advertises every seeded chart version (fix) — the baseline delete removes one"
VH_INDEX_AFTER="$(index_entries "$VH" "$ADMIN_TOKEN")"
if [ "$VH_INDEX_AFTER" = "$VH_INDEX_BEFORE" ] && [ "${VH_INDEX_AFTER:-0}" -gt 0 ]; then pass; else
  fail "the victim's chart index changed across the refused cross-repo DELETE: ${VH_INDEX_BEFORE} version entries before, ${VH_INDEX_AFTER} after (a zero here means the index could not be read at all)." \
    "before=${VH_INDEX_BEFORE} after=${VH_INDEX_AFTER} repo=${VH}"
fi

# ===========================================================================
# (FIX) — #3443's compatibility half. RED on the baseline as well, there
# because the alias failed CLOSED for a normally-named repository.
# ===========================================================================
begin_test "FIX: token scoped to its OWN normally-named repo reaches it through /api/cargo/{repo}/config.json -> 200 (baseline: the alias was dead)"
CC="$(code_get "${BASE_URL}/api/${DECOY_CARGO}/${OWN}/config.json" -H "Authorization: Bearer ${OWN_TOKEN}")"
if [ "$CC" = "200" ]; then pass; else
  fail "the /api/cargo alias did not resolve the repository key for its rightful, correctly-scoped owner: ${CC}, expected 200 (#3443 — the alias route is mounted but the middleware resolved the literal 'cargo' instead of '${OWN}', so the request was judged against the decoy: 403 when the caller's token is bound elsewhere, 401/404 otherwise)." \
    "code=${CC} repo=${OWN} token_scope=${OWN}"
fi

end_suite
