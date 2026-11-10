#!/usr/bin/env bash
# roles/web.sh - Jun Park, web lead at Halcyon Robotics.
#
# Jun runs the npm side: the local / remote / virtual trio of the web
# project, the remote's team-unlocked 7-day age gate and its review queue,
# and he checks that Leo's departure took effect for his team (ROLES.md,
# "web"). He also proves the virtual walk tells an outage apart from a miss
# (1.12.0 release notes, #5504/#5495): a member that cannot answer turns a
# miss into 503 + Retry-After, a member's permanent upstream 4xx stays 404.
#
# Personas: WEB_LEAD only (jwt:/basic:). No admin token.
# Barriers: signals web-age-gate-review; waits leo-offboarded (before #10)
#           and leo-verified (before #11: departed-employee's read-back of
#           Leo's package must finish before Jun deletes it)
#           (CS_BARRIER_TIMEOUT, default 600 s).
# Clients:  curl, jq, python3, tar; the real `npm` client for the client
#           checks (SKIP without it; CS_NODE_DIR=<node dir> adds <dir>/bin
#           to PATH). Upstream checks SKIP without registry.npmjs.org.
#
# Objects Jun creates and removes before the end (all in project HAL-web):
#   npm package ${HAL}-web-forms 1.0.0 + 1.1.0 in HAL-web-npm-local
#     (deleted at the end; republished with byte-identical tarballs on a
#     replay, which the tombstone check allows);
#   repositories ${HAL}-web-walk-down (npm remote, upstream on .invalid),
#   ${HAL}-web-walk-gone (npm remote, registry.npmjs.org),
#   ${HAL}-web-walk-mixed (virtual: down@1, gone@2),
#   ${HAL}-web-walk-miss (virtual: gone@1).
# Left behind on purpose: the age-gate review row Jun approves (the founder
# does not undo review decisions; a replay picks a different young version),
# and the upstream tarballs the remote cached.

source "$(dirname "$0")/../lib.sh"

cs_begin web
# Barriers this role signals: released as "failed" if it exits early.
cs_signals web-age-gate-review

BARRIER_TIMEOUT="${CS_BARRIER_TIMEOUT:-600}"
[ -n "${CS_NODE_DIR:-}" ] && PATH="${CS_NODE_DIR}/bin:${PATH}"

LOCAL="$HAL_REPO_WEB_NPM_LOCAL"
REMOTE="$HAL_REPO_WEB_NPM_REMOTE"
VIRT="$HAL_REPO_WEB_NPM"
FORMS="${HAL}-web-forms"
# Dist-tag a REST-delete cleanup (no npm client) leaves on ${FORMS}, read by
# the next day's #4: see the #5604 note there.
REST_MARK_TAG="rest-cleanup"
LEO_PKG="${HAL}-web-leo-widget"
NPM_UPSTREAM="${HAL_UPSTREAM_NPM:-https://registry.npmjs.org}"

_cs_work
W="$CS_WORK"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Is the public npm registry reachable from here? (upstream checks SKIP if not)
HAVE_NET=false
if curl -s -m 15 -o /dev/null -w '%{http_code}' "${NPM_UPSTREAM}/left-pad" 2>/dev/null | grep -q '^200$'; then
  HAVE_NET=true
fi

HAVE_NPM=false
command -v npm >/dev/null 2>&1 && command -v node >/dev/null 2>&1 && HAVE_NPM=true

# web_publish_npm KEY NAME VERSION AUTH - like cs_publish_npm, but the tarball
# is byte-identical on every run (gzip mtime 0), so a replay can republish a
# version that the previous run deleted: a tombstone with a different
# checksum answers 409 (handlers/mod.rs cleanup_soft_deleted_artifact_checked).
web_publish_npm() {
  local key="$1" name="$2" ver="$3" auth="$4"
  local out="${W}/${name//\//_}-${ver}.json"
  python3 -I - "$name" "$ver" "$BASE_URL" "$key" "$out" <<'PY'
import base64, gzip, io, json, sys, tarfile
name, ver, base, key, out = sys.argv[1:6]
raw = io.BytesIO()
with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as t:
    for p, data in (("package/package.json", json.dumps({"name": name, "version": ver, "main": "index.js", "license": "MIT"}).encode()),
                    ("package/index.js", b"module.exports = 'halcyon web forms';\n")):
        ti = tarfile.TarInfo(p); ti.size = len(data); ti.mtime = 1700000000; ti.mode = 0o644
        t.addfile(ti, io.BytesIO(data))
gz = io.BytesIO()
with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0) as g:
    g.write(raw.getvalue())
tb = gz.getvalue()
short = name.split("/")[-1]
doc = {"_id": name, "name": name, "dist-tags": {"latest": ver},
       "versions": {ver: {"name": name, "version": ver, "main": "index.js", "license": "MIT",
                          "dist": {"tarball": f"{base}/npm/{key}/{name}/-/{short}-{ver}.tgz"}}},
       "_attachments": {f"{short}-{ver}.tgz": {"content_type": "application/octet-stream",
                        "data": base64.b64encode(tb).decode(), "length": len(tb)}}}
json.dump(doc, open(out, "w"))
PY
  cs_http PUT "/npm/${key}/${name}" "$auth" -H 'Content-Type: application/json' --data-binary "@${out}"
}

# version recorded in the package.json of the tarball in CS_BODY_FILE
tarball_version() {
  tar -xzOf "$CS_BODY_FILE" package/package.json 2>/dev/null | jq -r '.version // empty' 2>/dev/null || true
}

# web_npm ARGS... - run the real npm client against this instance as Jun.
# Output in $W/npm.out; returns npm's exit code.
NPMRC="${W}/npmrc"
web_npm_setup() {
  cs_login WEB_LEAD || return 1
  local nerf="${BASE_URL#http://}"; nerf="${nerf#https://}"
  {
    echo "registry=${BASE_URL}/npm/${VIRT}/"
    for k in "$VIRT" "$LOCAL" "$REMOTE"; do
      echo "//${nerf}/npm/${k}/:_authToken=${CS_JWT[WEB_LEAD]}"
    done
    echo "update-notifier=false"
    echo "fund=false"
    echo "audit=false"
  } > "$NPMRC"
  chmod 600 "$NPMRC"
}
web_npm() {
  local rc=0
  ( cd "${NPM_DIR:-$W}" && \
    npm_config_userconfig="$NPMRC" npm_config_cache="${W}/npm-cache" \
    npm_config_globalconfig="${W}/npm-global-rc" npm_config_loglevel=warn \
    timeout 180 npm "$@" ) > "${W}/npm.out" 2>&1 || rc=$?
  return "$rc"
}
npm_out() { tail -c 400 "${W}/npm.out" | tr '\n' ' '; }

# Create one of Jun's own repositories in the web project unless it exists.
web_ensure_repo() {
  local body="$1" key
  key=$(printf '%s' "$body" | jq -r .key)
  cs_http GET "/api/v1/repositories/${key}" jwt:WEB_LEAD
  [ "$CS_STATUS" = "200" ] && return 0
  cs_http POST /api/v1/repositories jwt:WEB_LEAD -H 'Content-Type: application/json' -d "$body"
  [ "${CS_STATUS:0:1}" = "2" ]
}

# ---------------------------------------------------------------------------
# Morning: sign in
# ---------------------------------------------------------------------------
if cs_login WEB_LEAD; then
  cs_record "Jun signs in" PASS "JWT issued"
else
  cs_record "Jun signs in" FAIL "login HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
  cs_end
fi

# Replay hygiene: a previous run that stopped early may have left the forms
# package behind. Remove it with a whole-package npm unpublish, which also
# drops its npm_dist_tags row (H/npm.rs:6985). A REST delete would not: the
# `latest -> 1.0.0` pin of step 4 would survive and come back with the next
# 1.0.0 publish (see the cleanup note at the end).
$HAVE_NPM && web_npm_setup
cs_http GET "/npm/${LOCAL}/${FORMS}" basic:WEB_LEAD
if [ "$CS_STATUS" = "200" ]; then
  if $HAVE_NPM; then
    web_npm unpublish "$FORMS" --force --registry "${BASE_URL}/npm/${LOCAL}/" || true
  else
    for v in 1.0.0 1.1.0; do
      cs_http DELETE "/api/v1/repositories/${LOCAL}/artifacts/${FORMS}/${v}/${FORMS}-${v}.tgz" jwt:WEB_LEAD
    done
  fi
fi

# ---------------------------------------------------------------------------
# 1. Install the day-0 UI kit through the virtual (curl, then the npm client)
# ---------------------------------------------------------------------------
cs_http GET "/npm/${VIRT}/${HAL_SEED_NPM}" basic:WEB_LEAD
cs_expect "1 packument of day-0 ${HAL_SEED_NPM} through the virtual" 200
TARBALL_URL=$(cs_json ".versions[\"${HAL_SEED_NPM_VERSION}\"].dist.tarball // empty")
if [ -n "$TARBALL_URL" ]; then
  cs_http GET "$TARBALL_URL" basic:WEB_LEAD
  if cs_expect "1 day-0 tarball from versions[${HAL_SEED_NPM_VERSION}].dist.tarball" 200; then
    tv=$(tarball_version)
    if [ "$tv" = "$HAL_SEED_NPM_VERSION" ]; then
      cs_record "1 day-0 tarball is ${HAL_SEED_NPM}@${HAL_SEED_NPM_VERSION}" PASS "package.json version ${tv}"
    else
      cs_record "1 day-0 tarball is ${HAL_SEED_NPM}@${HAL_SEED_NPM_VERSION}" FAIL "package.json version '${tv}'"
    fi
  fi
else
  cs_record "1 day-0 tarball from versions[${HAL_SEED_NPM_VERSION}].dist.tarball" FAIL \
    "packument has no versions[\"${HAL_SEED_NPM_VERSION}\"].dist.tarball" "${CS_BODY:0:400}"
fi

if $HAVE_NPM && web_npm_setup; then
  NPM_DIR="${W}/app"; mkdir -p "$NPM_DIR"
  printf '{"name":"%s-web-app","version":"0.0.0","private":true}\n' "$HAL" > "${NPM_DIR}/package.json"
  if web_npm install --no-package-lock "${HAL_SEED_NPM}@${HAL_SEED_NPM_VERSION}" \
     && [ "$(jq -r .version "${NPM_DIR}/node_modules/${HAL_SEED_NPM}/package.json" 2>/dev/null)" = "$HAL_SEED_NPM_VERSION" ]; then
    cs_record "1 npm install ${HAL_SEED_NPM}@${HAL_SEED_NPM_VERSION} through the virtual (npm $(npm --version))" PASS "installed"
  else
    cs_record "1 npm install ${HAL_SEED_NPM}@${HAL_SEED_NPM_VERSION} through the virtual" FAIL "$(npm_out)"
  fi
  NPM_DIR=""
else
  cs_record "1 npm install ${HAL_SEED_NPM} through the virtual" SKIP "npm client not installed"
fi

# ---------------------------------------------------------------------------
# 2. Publish ${HAL}-web-forms 1.0.0 to the local
#    publish_package answers 200 {"ok":true} (H/npm.rs:6503-6577)
# ---------------------------------------------------------------------------
web_publish_npm "$LOCAL" "$FORMS" 1.0.0 jwt:WEB_LEAD
cs_expect "2 publish ${FORMS}@1.0.0 to the local (H/npm.rs:6574 200 ok)" 200
cs_expect_body "2 publish answer is {\"ok\":true}" '"ok":true'

# Same version again: duplicate path -> AppError::Conflict (H/npm.rs:6269-6275)
web_publish_npm "$LOCAL" "$FORMS" 1.0.0 jwt:WEB_LEAD
cs_expect "2 re-publish ${FORMS}@1.0.0 is refused (H/npm.rs:6270 Conflict)" 409

# ---------------------------------------------------------------------------
# 3. Its packument through the virtual lists 1.0.0
# ---------------------------------------------------------------------------
cs_http GET "/npm/${VIRT}/${FORMS}" basic:WEB_LEAD
if cs_expect "3 packument of ${FORMS} through the virtual" 200; then
  lt=$(cs_json '."dist-tags".latest // empty')
  [ "$lt" = "1.0.0" ] && cs_record "3 virtual dist-tags.latest == 1.0.0" PASS "latest ${lt}" \
                      || cs_record "3 virtual dist-tags.latest == 1.0.0" FAIL "latest '${lt}'" "${CS_BODY:0:400}"
fi

# ---------------------------------------------------------------------------
# 4. Publish 1.1.0 with the real npm client, then move latest back to 1.0.0
#    dist_tags_put answers 200 {"ok":true} (H/npm.rs:6635-6705)
# ---------------------------------------------------------------------------
if $HAVE_NPM; then
  PKG_DIR="${W}/forms"; mkdir -p "$PKG_DIR"
  printf '{"name":"%s","version":"1.1.0","main":"index.js","license":"MIT"}\n' "$FORMS" > "${PKG_DIR}/package.json"
  printf "module.exports = 'halcyon web forms 1.1';\n" > "${PKG_DIR}/index.js"
  NPM_DIR="$PKG_DIR"
  if web_npm publish --registry "${BASE_URL}/npm/${LOCAL}/"; then
    cs_record "4 npm publish ${FORMS}@1.1.0 to the local" PASS "npm exit 0"
  else
    cs_record "4 npm publish ${FORMS}@1.1.0 to the local" FAIL "$(npm_out)"
  fi
  NPM_DIR=""
else
  web_publish_npm "$LOCAL" "$FORMS" 1.1.0 jwt:WEB_LEAD
  cs_expect "4 publish ${FORMS}@1.1.0 to the local (wire, npm client missing)" 200
fi
cs_http GET "/npm/${LOCAL}/${FORMS}" basic:WEB_LEAD
lt=$(cs_json '."dist-tags".latest // empty')
mark=$(printf '%s' "$CS_BODY" | jq -r --arg t "$REST_MARK_TAG" '."dist-tags"[$t] // empty' 2>/dev/null || true)
if [ "$lt" = "1.1.0" ]; then
  cs_record "4 after 1.1.0 the local's latest is 1.1.0 (semver, #1543)" PASS "latest ${lt}"
elif [ "$lt" = "1.0.0" ] && [ -n "$mark" ]; then
  # The previous day removed ${FORMS} by REST DELETE (no npm client). That
  # leaves its dist-tag rows in npm_dist_tags (#5604, filed): the step-4
  # `latest -> 1.0.0` pin and the `rest-cleanup` marker it set just before
  # the delete. Both came back when 1.0.0 was republished; the marker's
  # presence proves the mechanism, so only this exact symptom is a WARN.
  cs_record "4 after 1.1.0 the local's latest is 1.1.0 (semver, #1543)" WARN \
    "#5604: latest '1.0.0' is yesterday's pin, resurrected with the '${REST_MARK_TAG}' tag after a REST delete"
else
  cs_record "4 after 1.1.0 the local's latest is 1.1.0 (semver, #1543)" FAIL "latest '${lt}' HTTP ${CS_STATUS}"
fi
if [ -n "$mark" ]; then
  cs_http DELETE "/npm/${LOCAL}/-/package/${FORMS}/dist-tags/${REST_MARK_TAG}" jwt:WEB_LEAD
  echo "  removed yesterday's ${REST_MARK_TAG} dist-tag -> HTTP ${CS_STATUS}"
fi

cs_http PUT "/npm/${LOCAL}/-/package/${FORMS}/dist-tags/latest" jwt:WEB_LEAD \
  -H 'Content-Type: application/json' --data-binary '"1.0.0"'
cs_expect "4 dist-tag latest -> 1.0.0 (H/npm.rs:6635 dist_tags_put)" 200
cs_http GET "/npm/${LOCAL}/${FORMS}" basic:WEB_LEAD
lt=$(cs_json '."dist-tags".latest // empty')
[ "$lt" = "1.0.0" ] && cs_record "4 local packument latest == 1.0.0" PASS "latest ${lt}" \
                    || cs_record "4 local packument latest == 1.0.0" FAIL "latest '${lt}' HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
cs_http GET "/npm/${VIRT}/${FORMS}" basic:WEB_LEAD
lt=$(cs_json '."dist-tags".latest // empty')
[ "$lt" = "1.0.0" ] && cs_record "4 virtual packument latest == 1.0.0 (local member wins the tag, H/npm.rs merge_packument_into)" PASS "latest ${lt}" \
                    || cs_record "4 virtual packument latest == 1.0.0 (local member wins the tag, H/npm.rs merge_packument_into)" FAIL "latest '${lt}' HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
if $HAVE_NPM; then
  if web_npm dist-tag ls "$FORMS" && grep -q '^latest: 1.0.0$' "${W}/npm.out"; then
    cs_record "4 npm dist-tag ls through the virtual shows latest: 1.0.0" PASS "$(npm_out)"
  else
    cs_record "4 npm dist-tag ls through the virtual shows latest: 1.0.0" FAIL "$(npm_out)"
  fi
fi

# ---------------------------------------------------------------------------
# 5. Pull an old upstream package through the virtual
# ---------------------------------------------------------------------------
if $HAVE_NET; then
  cs_http GET "/npm/${VIRT}/left-pad/-/left-pad-1.3.0.tgz" basic:WEB_LEAD
  cs_expect "5 left-pad 1.3.0 (2018) through the virtual" 200
  if $HAVE_NPM; then
    NPM_DIR="${W}/app"
    if web_npm install --no-package-lock left-pad@1.3.0 \
       && [ "$(jq -r .version "${NPM_DIR}/node_modules/left-pad/package.json" 2>/dev/null)" = "1.3.0" ]; then
      cs_record "5 npm install left-pad@1.3.0 through the virtual" PASS "installed"
    else
      cs_record "5 npm install left-pad@1.3.0 through the virtual" FAIL "$(npm_out)"
    fi
    NPM_DIR=""
  fi
else
  cs_record "5 left-pad 1.3.0 through the virtual" SKIP "no route to ${NPM_UPSTREAM}"
fi

# ---------------------------------------------------------------------------
# 6. Read the age gate (unlocked, team-operated; H/age_gate.rs:47-52, 257-265)
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/repositories/${REMOTE}/age-gate" jwt:WEB_LEAD
if cs_expect "6 Jun reads the npm remote's age gate (repo admin via project grant, #4238)" 200; then
  got=$(cs_json '"enabled=\(.enabled) min_age_days=\(.min_age_days) mode=\(.mode) instance_locked=\(.instance_locked)"')
  if [ "$got" = "enabled=true min_age_days=7 mode=upstream_publish_time instance_locked=false" ]; then
    cs_record "6 gate is enabled, 7 days, upstream_publish_time, unlocked" PASS "$got"
  else
    cs_record "6 gate is enabled, 7 days, upstream_publish_time, unlocked" FAIL "$got"
  fi
fi

# ---------------------------------------------------------------------------
# 7-9. Trigger the gate with a version younger than 7 days, find the review,
#      approve it as repository admin and fetch it again.
# ---------------------------------------------------------------------------
REVIEW_ID=""
if ! $HAVE_NET; then
  cs_record "7 age gate on a young upstream version" SKIP "no route to ${NPM_UPSTREAM}"
else
  # Reviews already on this repo (earlier runs): their versions are decided,
  # so a replay must pick another young version.
  cs_http GET "/api/v1/repositories/${REMOTE}/age-gate/reviews?per_page=100" jwt:WEB_LEAD
  printf '%s' "$CS_BODY" | jq -r '.items[]? | "\(.package_name)@\(.package_version)"' > "${W}/known-reviews" 2>/dev/null || : > "${W}/known-reviews"
  # Pick an unscoped package with a version published in the last 6 days.
  # Prefer one the remote has never cached: with a last-known-good cached the
  # gate serves the older tarball instead of 451 (H/proxy_helpers.rs:9971-10036).
  cs_http GET "/api/v1/repositories/${REMOTE}/artifacts?per_page=1000" jwt:WEB_LEAD
  printf '%s' "$CS_BODY" | jq -r '.items[]?.name // empty' 2>/dev/null | sort -u > "${W}/remote-cached" || : > "${W}/remote-cached"
  PICK=$(python3 -I - "$NPM_UPSTREAM" "${W}/known-reviews" "${W}/remote-cached" <<'PY'
import datetime, json, sys, urllib.request
up, known_f, cached_f = sys.argv[1:4]
known = set(open(known_f).read().split())
cached = set(open(cached_f).read().split())
now = datetime.datetime.now(datetime.timezone.utc)
cands = ["typescript", "next", "react", "react-dom", "vite", "eslint", "webpack", "prettier"]
best = []
for pkg in cands:
    try:
        with urllib.request.urlopen(f"{up}/{pkg}", timeout=60) as r:
            doc = json.load(r)
    except Exception:
        continue
    times = doc.get("time", {})
    for ver in doc.get("versions", {}):
        t = times.get(ver)
        if not t:
            continue
        ts = datetime.datetime.fromisoformat(t.replace("Z", "+00:00"))
        age = (now - ts).total_seconds() / 86400
        if 0.02 < age < 6.0 and f"{pkg}@{ver}" not in known:
            best.append((pkg in cached, age, pkg, ver))
    if any(not c for c, *_ in best):
        break
best.sort()
if best:
    c, age, pkg, ver = best[0]
    print(f"{pkg} {ver} {age:.2f} {'cached' if c else 'uncached'}")
PY
)
  if [ -z "$PICK" ]; then
    cs_record "7 age gate on a young upstream version" SKIP "no candidate version younger than 6 days found upstream"
  else
    read -r YPKG YVER YAGE YCACHED <<<"$PICK"
    YFILE="${YPKG}-${YVER}.tgz"
    cs_http GET "/npm/${REMOTE}/${YPKG}/-/${YFILE}" basic:WEB_LEAD
    st="$CS_STATUS"
    if [ "$st" = "451" ]; then
      REVIEW_ID=$(cs_json '.review_id // empty')
      cc=$(cs_header Cache-Control)
      err=$(cs_json '.error // empty')
      if [ "$err" = "age_gate_blocked" ] && [ -n "$REVIEW_ID" ] && [ "$cc" = "no-store" ]; then
        cs_record "7 ${YPKG}@${YVER} (${YAGE} d old, ${YCACHED}) through the remote: 451 age_gate_blocked" PASS \
          "HTTP 451, review_id ${REVIEW_ID}, Cache-Control: ${cc} (H/proxy_helpers.rs:9496-9541)"
      else
        cs_record "7 ${YPKG}@${YVER} through the remote: 451 age_gate_blocked" FAIL \
          "451 but error='${err}' review_id='${REVIEW_ID}' Cache-Control='${cc}'" "${CS_BODY:0:400}"
      fi
    elif [ "$st" = "200" ]; then
      tv=$(tarball_version)
      if [ -n "$tv" ] && [ "$tv" != "$YVER" ]; then
        cs_record "7 ${YPKG}@${YVER} (${YAGE} d old, ${YCACHED}) through the remote: last-known-good ${tv} served" PASS \
          "HTTP 200 with the older tarball ${tv}, as H/npm.rs:5138-5142 substitutes when an LKG is cached"
      else
        cs_record "7 ${YPKG}@${YVER} (${YAGE} d old) through the remote is held by the age gate" FAIL \
          "HTTP 200 served the young version itself ('${tv}'); expected 451 or an LKG substitute (H/proxy_helpers.rs:9971-10036)"
      fi
    else
      cs_record "7 ${YPKG}@${YVER} through the remote is held by the age gate" FAIL \
        "expected 451 (or 200 LKG), got ${st} (${CS_LAST_REQ})" "${CS_BODY:0:400}"
    fi

    # 8. the repository review queue
    cs_signal web-age-gate-review
    cs_http GET "/api/v1/repositories/${REMOTE}/age-gate/reviews?per_page=100" jwt:WEB_LEAD
    if cs_expect "8 Jun lists the remote's review queue (H/age_gate.rs:805, #4238)" 200; then
      row=$(printf '%s' "$CS_BODY" | jq -c --arg p "$YPKG" --arg v "$YVER" \
        '[.items[]? | select(.package_name==$p and .package_version==$v)][0] // empty' 2>/dev/null)
      rid=$(printf '%s' "$row" | jq -r '.id // empty' 2>/dev/null)
      if [ -n "$rid" ] && { [ -z "$REVIEW_ID" ] || [ "$rid" = "$REVIEW_ID" ]; }; then
        REVIEW_ID="$rid"
        cs_record "8 queue holds the review for ${YPKG}@${YVER}" PASS \
          "id ${rid}, status $(printf '%s' "$row" | jq -r .status), instance_locked $(printf '%s' "$row" | jq -r .instance_locked)"
      else
        cs_record "8 queue holds the review for ${YPKG}@${YVER}" FAIL \
          "no row for ${YPKG}@${YVER} matching review_id '${REVIEW_ID}' (found '${rid}')" "${CS_BODY:0:400}"
        REVIEW_ID=""
      fi
    fi

    # 9. approve as repository admin, fetch again
    if [ -n "$REVIEW_ID" ]; then
      cs_http POST "/api/v1/repositories/${REMOTE}/age-gate/reviews/${REVIEW_ID}/approve" jwt:WEB_LEAD \
        -H 'Content-Type: application/json' -d '{"reason":"needed for release"}'
      if cs_expect "9 Jun approves the review as repo admin (H/age_gate.rs:873)" 200; then
        s=$(cs_json '.status // empty'); by=$(cs_json '.reviewed_by_username // empty')
        [ "$s" = "approved" ] && [ "$by" = "$HAL_WEB_LEAD_USER" ] \
          && cs_record "9 review is approved by ${HAL_WEB_LEAD_USER}" PASS "status ${s}, reviewed_by_username ${by}" \
          || cs_record "9 review is approved by ${HAL_WEB_LEAD_USER}" FAIL "status '${s}', reviewed_by_username '${by}'"
      fi
      cs_http GET "/npm/${REMOTE}/${YPKG}/-/${YFILE}" basic:WEB_LEAD
      if cs_expect "9 after approval ${YFILE} downloads" 200; then
        tv=$(tarball_version)
        [ "$tv" = "$YVER" ] && cs_record "9 the approved tarball is ${YPKG}@${YVER} itself" PASS "package.json ${tv}" \
                            || cs_record "9 the approved tarball is ${YPKG}@${YVER} itself" FAIL "package.json '${tv}'"
      fi
    else
      cs_record "9 approve the review" SKIP "no review id from 7/8"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Virtual walk: outage vs miss (#5504, #5495; RN:46; H/proxy_helpers.rs:837-844,
# error.rs:548-551). Jun builds his own throwaway members in the web project.
# ---------------------------------------------------------------------------
DOWN="${HAL}-web-walk-down"; GONE="${HAL}-web-walk-gone"
VMIX="${HAL}-web-walk-mixed"; VMISS="${HAL}-web-walk-miss"
NOPKG="${HAL}-web-no-such-package"
walk_ok=true
for spec in \
  "$(jq -nc --arg k "$DOWN" --arg p "$HAL_PROJECT_WEB_ID" --arg u "http://${HAL}-npm-outage.invalid" \
      '{key:$k,name:$k,format:"npm",repo_type:"remote",visibility:"private",project_id:$p,upstream_url:$u}')" \
  "$(jq -nc --arg k "$GONE" --arg p "$HAL_PROJECT_WEB_ID" --arg u "$NPM_UPSTREAM" \
      '{key:$k,name:$k,format:"npm",repo_type:"remote",visibility:"private",project_id:$p,upstream_url:$u}')" \
  "$(jq -nc --arg k "$VMIX" --arg p "$HAL_PROJECT_WEB_ID" \
      '{key:$k,name:$k,format:"npm",repo_type:"virtual",visibility:"private",project_id:$p}')" \
  "$(jq -nc --arg k "$VMISS" --arg p "$HAL_PROJECT_WEB_ID" \
      '{key:$k,name:$k,format:"npm",repo_type:"virtual",visibility:"private",project_id:$p}')"; do
  k=$(printf '%s' "$spec" | jq -r .key)
  if ! web_ensure_repo "$spec"; then
    cs_record "walk: Jun creates ${k} in the web project (project admin, RS:4634-4655)" FAIL \
      "HTTP ${CS_STATUS} (${CS_LAST_REQ})" "${CS_BODY:0:300}"
    walk_ok=false
  fi
done
add_member() {
  local v="$1" m="$2" p="$3"
  cs_http GET "/api/v1/repositories/${v}/members" jwt:WEB_LEAD
  if printf '%s' "$CS_BODY" | jq -e --arg m "$m" '(.members // .items // [])[]? | select(.member_repo_key==$m)' >/dev/null 2>&1; then
    return 0
  fi
  cs_http POST "/api/v1/repositories/${v}/members" jwt:WEB_LEAD -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg m "$m" --argjson p "$p" '{member_key:$m,priority:$p}')"
  [ "${CS_STATUS:0:1}" = "2" ]
}
if $walk_ok; then
  cs_record "walk: Jun creates 2 npm remotes and 2 virtuals in the web project" PASS "${DOWN} ${GONE} ${VMIX} ${VMISS}"
  for mspec in "$VMIX $DOWN 1" "$VMIX $GONE 2" "$VMISS $GONE 1"; do
    read -r v m p <<<"$mspec"
    if ! add_member "$v" "$m" "$p"; then
      cs_record "walk: add ${m}@${p} to ${v}" FAIL "HTTP ${CS_STATUS} (${CS_LAST_REQ})" "${CS_BODY:0:300}"
      walk_ok=false
    fi
  done
fi
if ! $walk_ok; then
  cs_record "walk: outage vs miss" SKIP "fixture repositories could not be set up"
elif ! $HAVE_NET; then
  cs_record "walk: outage vs miss" SKIP "no route to ${NPM_UPSTREAM}"
else
  # (a) nothing serves, one member is down -> 503 + Retry-After
  cs_http GET "/npm/${VMIX}/${NOPKG}/-/${NOPKG}-1.0.0.tgz" basic:WEB_LEAD
  if cs_expect "walk: miss on a virtual with an unreachable member answers 503 (RN:46, #5504)" 503; then
    ra=$(cs_header Retry-After); code=$(cs_json '.code // empty')
    [ -n "$ra" ] && [ "$code" = "SERVICE_UNAVAILABLE" ] \
      && cs_record "walk: the 503 carries Retry-After and SERVICE_UNAVAILABLE (error.rs:548-551)" PASS "Retry-After: ${ra}; $(cs_json .message)" \
      || cs_record "walk: the 503 carries Retry-After and SERVICE_UNAVAILABLE (error.rs:548-551)" FAIL "Retry-After '${ra}', code '${code}'" "${CS_BODY:0:300}"
  fi
  # (b) the only member answers a permanent upstream 404 -> 404, no Retry-After
  cs_http GET "/npm/${VMISS}/${NOPKG}/-/${NOPKG}-1.0.0.tgz" basic:WEB_LEAD
  if cs_expect "walk: miss on a virtual whose member answers upstream 404 stays 404 (RN:46, #5495)" 404; then
    ra=$(cs_header Retry-After)
    [ -z "$ra" ] && cs_record "walk: the 404 has no Retry-After" PASS "no Retry-After" \
                 || cs_record "walk: the 404 has no Retry-After" FAIL "Retry-After: ${ra}"
  fi
  # (c) the walk passes over the down member and serves from the next one
  cs_http GET "/npm/${VMIX}/left-pad/-/left-pad-1.3.0.tgz" basic:WEB_LEAD
  cs_expect "walk: left-pad 1.3.0 is served by the lower-priority member past the unreachable one (RN:46)" 200
  # (d) the packument merge is not the artifact walk: an unreachable member's
  # contribution is Ok(None) (H/npm.rs:4466-4486), so a miss stays 404 there.
  cs_http GET "/npm/${VMIX}/${NOPKG}" basic:WEB_LEAD
  cs_expect "walk: packument miss on the virtual with an unreachable member is 404 (H/npm.rs:4346-4349, 4466-4486)" 404 \
    "the packument merge has no 503 path; RN:46 covers artifacts and checksums"
fi
# Clean the walk fixtures (virtuals first). DELETE answers 202 with a job (#4311).
for k in "$VMIX" "$VMISS" "$DOWN" "$GONE"; do
  cs_http GET "/api/v1/repositories/${k}" jwt:WEB_LEAD
  [ "$CS_STATUS" = "200" ] || continue
  cs_http DELETE "/api/v1/repositories/${k}" jwt:WEB_LEAD
  cs_expect "walk cleanup: Jun deletes ${k} (RN #4311)" 202
done

# ---------------------------------------------------------------------------
# Should NOT work
# ---------------------------------------------------------------------------
# Firmware's locked gate: Jun cannot read that repo, so the write gate hides
# it (#5458 covers .../age-gate, RN:45).
cs_http PUT "/api/v1/repositories/${HAL_REPO_FW_MAVEN_REMOTE}/age-gate" jwt:WEB_LEAD \
  -H 'Content-Type: application/json' -d '{"enabled":false,"min_age_days":0,"mode":"upstream_publish_time"}'
cs_expect "NOT: Jun changes the firmware remote's age gate -> 404 (#5458, RN:45)" 404

# Instance-wide review queue is admin_middleware (H/age_gate.rs:38-45, R:1428)
cs_http GET /api/v1/admin/age-gate/reviews jwt:WEB_LEAD
if cs_expect "NOT: Jun reads the instance-wide review queue -> 403" 403; then
  cs_expect_body "NOT: the 403 says Admin access required" "Admin access required"
fi

# A repository admin may not set the lock (S/age_gate_service.rs:1640-1645).
# Same values as the founded policy, so even a wrong 200 only adds the lock.
cs_http PUT "/api/v1/repositories/${REMOTE}/age-gate" jwt:WEB_LEAD \
  -H 'Content-Type: application/json' \
  -d '{"enabled":true,"min_age_days":7,"mode":"upstream_publish_time","instance_locked":true}'
cs_expect "NOT: Jun sends instance_locked:true on his own gate -> 403 (H/age_gate.rs:142-148)" 403
cs_http GET "/api/v1/repositories/${REMOTE}/age-gate" jwt:WEB_LEAD
il=$(cs_json '.instance_locked')
[ "$il" = "false" ] && cs_record "NOT: the gate is still unlocked afterwards" PASS "instance_locked false" \
                    || cs_record "NOT: the gate is still unlocked afterwards" FAIL "instance_locked '${il}' HTTP ${CS_STATUS}"

# ---------------------------------------------------------------------------
# 10-12. After Leo is offboarded
# ---------------------------------------------------------------------------
if cs_wait leo-offboarded "$BARRIER_TIMEOUT"; then
  cs_http GET "/api/v1/groups/${HAL_GROUP_WEB_ID}?member_limit=200" jwt:WEB_LEAD
  if cs_expect "10 Jun reads his group after Leo left (H/groups.rs:39-70)" 200; then
    ids=$(cs_json '[.members[]? | (.user_id // .id)] | sort | join(",")')
    [ "$ids" = "$HAL_WEB_LEAD_ID" ] \
      && cs_record "10 ${HAL_GROUP_WEB} members == [${HAL_WEB_LEAD_USER}]" PASS "members ${ids}" \
      || cs_record "10 ${HAL_GROUP_WEB} members == [${HAL_WEB_LEAD_USER}]" FAIL "member ids '${ids}' (jun ${HAL_WEB_LEAD_ID}, leo ${HAL_WEB_DEV_ID})" "${CS_BODY:0:400}"
  fi

  if ! cs_wait leo-verified "$BARRIER_TIMEOUT"; then
    cs_record "waited for leo-verified" FAIL "${CS_WAIT_WHY}; deleting anyway"
  fi
  cs_http GET "/npm/${VIRT}/${LEO_PKG}" basic:WEB_LEAD
  cs_expect "11 Leo's ${LEO_PKG} is still served through the virtual (deactivation removes access, not content)" 200
  LEO_VERS=$(cs_json '.versions | keys[]?' | tr '\n' ' ')

  if [ -z "$LEO_VERS" ]; then
    cs_record "12 Jun deletes Leo's package" SKIP "no versions of ${LEO_PKG} found"
  else
    for v in $LEO_VERS; do
      cs_http DELETE "/api/v1/repositories/${LOCAL}/artifacts/${LEO_PKG}/${v}/${LEO_PKG}-${v}.tgz" jwt:WEB_LEAD
      cs_expect "12 Jun deletes Leo's ${LEO_PKG}@${v} via REST (RS:13777-13800)" 200
    done
    cs_http GET "/npm/${VIRT}/${LEO_PKG}" basic:WEB_LEAD
    cs_expect "12 ${LEO_PKG} is gone afterwards" 404
  fi
else
  cs_record "waited for leo-offboarded" FAIL "${CS_WAIT_WHY} (platform-admin)"
fi

# ---------------------------------------------------------------------------
# End of day: remove ${FORMS} with a whole-package npm unpublish (#4025).
# Not REST: a REST delete of 1.0.0 leaves the step-4 `latest -> 1.0.0` row in
# npm_dist_tags (only unpublish_npm_rows / unpublish_package_for touch it,
# H/npm.rs:6909-6919, 6985), and the next 1.0.0 publish brings the pin back,
# so a later 1.1.0 is not `latest`.
# ---------------------------------------------------------------------------
if $HAVE_NPM; then
  if web_npm unpublish "$FORMS" --force --registry "${BASE_URL}/npm/${LOCAL}/"; then
    cs_record "cleanup: npm unpublish ${FORMS} (whole package)" PASS "npm exit 0"
  else
    cs_record "cleanup: npm unpublish ${FORMS} (whole package)" FAIL "$(npm_out)"
  fi
else
  # Mark the package before the REST deletes: the tag row outlives them, as
  # the latest pin does (#5604), and tomorrow's #4 reads it.
  cs_http PUT "/npm/${LOCAL}/-/package/${FORMS}/dist-tags/${REST_MARK_TAG}" jwt:WEB_LEAD \
    -H 'Content-Type: application/json' --data-binary '"1.0.0"'
  cs_expect "cleanup: tag ${FORMS}@1.0.0 '${REST_MARK_TAG}' before the REST deletes" 200
  for v in 1.1.0 1.0.0; do
    cs_http DELETE "/api/v1/repositories/${LOCAL}/artifacts/${FORMS}/${v}/${FORMS}-${v}.tgz" jwt:WEB_LEAD
    cs_expect "cleanup: delete ${FORMS}@${v} via REST (npm client missing; RS:13777-13800)" 200
  done
fi
cs_http GET "/npm/${LOCAL}/${FORMS}" basic:WEB_LEAD
cs_expect "cleanup: ${FORMS} is gone from the local" 404

cs_end
