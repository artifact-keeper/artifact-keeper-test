#!/usr/bin/env bash
# roles/data.sh - Sofia Mendes (data lead) and Arjun Das (data engineer) at
# Halcyon Robotics.
#
# The data team ships Python and conda packages. Arjun installs the day-0
# telemetry library, publishes an ETL package (twine-style curl, then the real
# `uv build` / `uv publish` / `pip install` / `uv pip install` path through
# the team's virtual index), and publishes a conda package. Sofia, who
# administers the HAL-data project, tunes the age gate on the PyPI remote
# that the platform team handed to her (instance_locked: false).
#
# Real clients: `uv` (PATH or ~/.local/bin) provides uv build/publish, a venv
# seeded with pip (through the team index) and uv pip. Without uv those checks
# SKIP. The conda package is built with the minimal .tar.bz2 layout of
# tests/formats/test-conda.sh. A real conda client (pixi) runs only when
# HAL_CONDA_CLIENT_IMAGE names a local podman/docker image with `pixi` in it;
# otherwise that check SKIPs.
#
# Left behind (no data persona may remove them):
#   - ${HAL}-data-etl <ETL_VER> sdist and wheel in HAL-data-pypi-local: a
#     PyPI package file is immutable, and REST DELETE by a non-admin answers
#     409 (repositories.rs delete_blocked_by_immutability); task 11 pins that.
#   - ${HAL}-data-model <ETL_VER> in HAL-data-conda-local: conda withdraw is
#     instance-admin only (conda.rs withdraw_package) and REST delete is
#     blocked the same way.
# Every run uses a fresh version (0.1.<epoch>), so replays never collide.
#
# Barriers: none (data neither signals nor waits).

source "$(dirname "$0")/../lib.sh"

cs_begin data

ETL_VER="0.1.$(date +%s)"
ETL_NAME="${HAL}-data-etl"                 # PEP 503 normal form already
ETL_MOD="${ETL_NAME//-/_}"
ETL_SDIST="${ETL_MOD}-${ETL_VER}.tar.gz"   # cs_publish_pypi's filename
ETL_WHEEL="${ETL_MOD}-${ETL_VER}-py3-none-any.whl"
CONDA_NAME="${HAL}-data-model"
CONDA_FILE="${CONDA_NAME}-${ETL_VER}-0.tar.bz2"
SEED_NORM="${HAL_SEED_PYPI}"               # halcyon-telemetry

_cs_work
W="${CS_WORK}/data"
mkdir -p "$W"

# url_with_creds URL USER SECRET - URL with percent-encoded Basic credentials.
url_with_creds() {
  python3 -I -c 'import sys, urllib.parse as u
p = u.urlsplit(sys.argv[1])
cred = u.quote(sys.argv[2], safe="") + ":" + u.quote(sys.argv[3], safe="")
print(u.urlunsplit((p.scheme, cred + "@" + p.netloc, p.path, p.query, p.fragment)))' "$1" "$2" "$3"
}

# run_logged NAME CMD... - run a client command, keep its output in $W/NAME.log.
# Returns the command's exit code.
run_logged() {
  local n="$1"; shift
  "$@" > "${W}/${n}.log" 2>&1
}
log_tail() { tail -n 15 "${W}/$1.log" 2>/dev/null | tr '\n' ' ' | cut -c1-500; }

# ---------------------------------------------------------------------------
# Morning: sign in
# ---------------------------------------------------------------------------
for p in DATA_LEAD DATA_DEV; do
  if cs_login "$p"; then
    cs_record "${p} signs in" PASS "JWT issued"
  else
    cs_record "${p} signs in" FAIL "login HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
    cs_end
  fi
done

# ---------------------------------------------------------------------------
# Task 1: Arjun installs the day-0 halcyon-telemetry through the virtual.
# Expected: simple page 200, sdist href 200, bytes match #sha256= fragment.
# ---------------------------------------------------------------------------
cs_http GET "/pypi/${HAL_REPO_DATA_PYPI}/simple/${SEED_NORM}/" basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN
if cs_expect "1a Arjun reads the simple page of ${SEED_NORM} through the virtual" 200; then
  href=$(printf '%s' "$CS_BODY" | grep -o 'href="[^"]*\.tar\.gz#sha256=[0-9a-f]*"' | head -n1 | sed -e 's/^href="//' -e 's/"$//' || true)
  if [ -z "$href" ]; then
    cs_record "1b sdist href on the simple page" FAIL "no .tar.gz#sha256 href" "${CS_BODY:0:600}"
  else
    want_sha="${href##*#sha256=}"
    link="${href%%#*}"
    case "$link" in
      http://*|https://*) ;;
      /*) ;;
      *) link="/pypi/${HAL_REPO_DATA_PYPI}/simple/${SEED_NORM}/${link}" ;;
    esac
    cs_http GET "$link" basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN -L
    if cs_expect "1b Arjun downloads the ${SEED_NORM} sdist through the virtual" 200; then
      got_sha=$(sha256sum "$CS_BODY_FILE" | cut -d' ' -f1)
      if [ "$got_sha" = "$want_sha" ]; then
        cs_record "1c sdist sha256 matches the href fragment" PASS "sha256 ${got_sha:0:16}..."
      else
        cs_record "1c sdist sha256 matches the href fragment" FAIL "fragment ${want_sha}, body ${got_sha}"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Task 2/3: Arjun uploads ${HAL}-data-etl twine-style with his token, then the
# same filename again.
# Expected: 200 (H/pypi.rs upload); duplicate path is 409 Conflict
# "File already exists" (H/pypi.rs, `existing.is_some()` check in upload).
# ---------------------------------------------------------------------------
cs_publish_pypi "$HAL_REPO_DATA_PYPI_LOCAL" "$ETL_NAME" "$ETL_VER" basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN
cs_expect "2 Arjun uploads ${ETL_NAME} ${ETL_VER} sdist (twine-style, personal token)" 200
cs_publish_pypi "$HAL_REPO_DATA_PYPI_LOCAL" "$ETL_NAME" "$ETL_VER" basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN
if cs_expect "3 re-upload of the same sdist filename is refused (pypi.rs: Conflict 'File already exists')" 409; then
  cs_expect_body "3b re-upload answer says the file exists" "File already exists"
fi

# ---------------------------------------------------------------------------
# Task 4: the virtual's simple root lists both packages (normalised names).
# ---------------------------------------------------------------------------
cs_http GET "/pypi/${HAL_REPO_DATA_PYPI}/simple/" basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN
if cs_expect "4 simple root through the virtual" 200; then
  cs_expect_body "4b simple root lists ${SEED_NORM}" ">${SEED_NORM}<"
  cs_expect_body "4c simple root lists ${ETL_NAME}" ">${ETL_NAME}<"
fi

# ---------------------------------------------------------------------------
# Task 5: an old upstream package through the virtual (remote pypi.org).
# Older than 7 days, so the age gate lets it through.
# ---------------------------------------------------------------------------
if curl -s -o /dev/null -m 10 "${HAL_UPSTREAM_PYPI:-https://pypi.org}/simple/six/" 2>/dev/null; then
  cs_http GET "/pypi/${HAL_REPO_DATA_PYPI}/simple/six/" basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN
  if cs_expect "5 upstream 'six' simple page through the virtual" 200; then
    cs_expect_body "5b six page links six-1.16.0" "six-1.16.0"
  fi
  HAVE_NET=true
else
  cs_record "5 upstream 'six' simple page through the virtual" SKIP "upstream PyPI unreachable from the runner"
  HAVE_NET=false
fi

# ---------------------------------------------------------------------------
# Real clients: uv build (build deps through the virtual), uv publish with
# Arjun's token, then pip and uv pip install through the virtual.
# ---------------------------------------------------------------------------
UV="$(command -v uv 2>/dev/null || true)"
[ -z "$UV" ] && [ -x "${HOME}/.local/bin/uv" ] && UV="${HOME}/.local/bin/uv"
VIRT_URL="${BASE_URL}/pypi/${HAL_REPO_DATA_PYPI}/simple/"
LOCAL_UP="${BASE_URL}/pypi/${HAL_REPO_DATA_PYPI_LOCAL}/"
if [ -z "$UV" ]; then
  for c in "R1 uv build" "R2 uv publish" "R3 pip install" "R4 uv pip install"; do
    cs_record "$c (${ETL_NAME})" SKIP "uv not installed"
  done
elif ! $HAVE_NET; then
  for c in "R1 uv build" "R2 uv publish" "R3 pip install" "R4 uv pip install"; do
    cs_record "$c (${ETL_NAME})" SKIP "no upstream PyPI: build deps and pip cannot be resolved"
  done
else
  export UV_CACHE_DIR="${W}/uv-cache" UV_NO_CONFIG=1 UV_PYTHON_DOWNLOADS=never
  IDX=$(url_with_creds "$VIRT_URL" "$HAL_DATA_DEV_USER" "$HAL_DATA_DEV_TOKEN")
  export UV_DEFAULT_INDEX="$IDX"
  proj="${W}/etl"
  mkdir -p "${proj}/src/${ETL_MOD}"
  cat > "${proj}/pyproject.toml" <<EOF
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "${ETL_NAME}"
version = "${ETL_VER}"
description = "Halcyon Robotics telemetry ETL"
requires-python = ">=3.8"
dependencies = ["six"]
EOF
  printf 'ROLE = "data"\nVERSION = "%s"\n' "$ETL_VER" > "${proj}/src/${ETL_MOD}/__init__.py"

  # R1: build a wheel; hatchling and its deps resolve through the team index.
  if run_logged uv-build "$UV" build --wheel --out-dir "${W}/dist" "$proj" && [ -f "${W}/dist/${ETL_WHEEL}" ]; then
    cs_record "R1 uv build wheel (build backend via the virtual index)" PASS "${ETL_WHEEL}"
    # R2: real uv publish with Arjun's token (Basic user:token on the native route).
    if run_logged uv-publish "$UV" publish --publish-url "$LOCAL_UP" \
         --username "$HAL_DATA_DEV_USER" --password "$HAL_DATA_DEV_TOKEN" "${W}/dist/${ETL_WHEEL}"; then
      cs_record "R2 uv publish wheel with Arjun's token" PASS "uploaded ${ETL_WHEEL}"
    else
      cs_record "R2 uv publish wheel with Arjun's token" FAIL "uv publish failed: $(log_tail uv-publish)"
    fi
  else
    cs_record "R1 uv build wheel (build backend via the virtual index)" FAIL "$(log_tail uv-build)"
    cs_record "R2 uv publish wheel with Arjun's token" SKIP "no wheel built"
  fi

  # R3: a venv seeded with pip through the team index, then pip install.
  if run_logged venv-pip "$UV" venv --seed --python python3 "${W}/venv-pip"; then
    if run_logged pip-install "${W}/venv-pip/bin/python" -m pip install --no-cache-dir \
         --disable-pip-version-check --index-url "$IDX" "${ETL_NAME}==${ETL_VER}" \
       && run_logged pip-import "${W}/venv-pip/bin/python" -c "import ${ETL_MOD}, six; assert ${ETL_MOD}.VERSION == '${ETL_VER}'"; then
      cs_record "R3 pip install ${ETL_NAME}==${ETL_VER} (+six) through the virtual, imports" PASS \
        "$(grep -o 'Successfully installed.*' "${W}/pip-install.log" | cut -c1-200)"
    else
      cs_record "R3 pip install ${ETL_NAME}==${ETL_VER} (+six) through the virtual, imports" FAIL \
        "$(log_tail pip-install) $(log_tail pip-import)"
    fi
  else
    cs_record "R3 pip install ${ETL_NAME}==${ETL_VER} (+six) through the virtual, imports" FAIL \
      "uv venv --seed (pip from the virtual) failed: $(log_tail venv-pip)"
  fi

  # R4: uv pip install into a fresh venv.
  if run_logged venv-uv "$UV" venv --python python3 "${W}/venv-uv" \
     && run_logged uv-pip-install "$UV" pip install --python "${W}/venv-uv/bin/python" --no-cache \
          "${ETL_NAME}==${ETL_VER}" \
     && run_logged uv-import "${W}/venv-uv/bin/python" -c "import ${ETL_MOD}, six; assert ${ETL_MOD}.VERSION == '${ETL_VER}'"; then
    cs_record "R4 uv pip install ${ETL_NAME}==${ETL_VER} (+six) through the virtual, imports" PASS "installed"
  else
    cs_record "R4 uv pip install ${ETL_NAME}==${ETL_VER} (+six) through the virtual, imports" FAIL \
      "$(log_tail venv-uv) $(log_tail uv-pip-install) $(log_tail uv-import)"
  fi
  unset UV_DEFAULT_INDEX
fi

# ---------------------------------------------------------------------------
# Task 6/7: the PyPI remote's age gate belongs to the data lead.
# Expected: GET 200 instance_locked:false (found-policies.sh); PUT first_seen
# 200 and back to upstream_publish_time 200 (H/age_gate.rs:134-149, #4238).
# ---------------------------------------------------------------------------
AG="/api/v1/repositories/${HAL_REPO_DATA_PYPI_REMOTE}/age-gate"
cs_http GET "$AG" jwt:DATA_LEAD
if cs_expect "6 Sofia reads the PyPI remote age gate" 200; then
  if [ "$(cs_json '.instance_locked')" = "false" ] && [ "$(cs_json '.enabled')" = "true" ]; then
    cs_record "6b age gate is enabled and team-unlocked" PASS \
      "min_age_days=$(cs_json '.min_age_days') mode=$(cs_json '.mode') instance_locked=false"
  else
    cs_record "6b age gate is enabled and team-unlocked" FAIL "got ${CS_BODY:0:300}"
  fi
fi
AG_DAYS="${HAL_AGE_GATE_DAYS:-7}"
cs_http PUT "$AG" jwt:DATA_LEAD -H 'Content-Type: application/json' \
  -d "{\"enabled\":true,\"min_age_days\":${AG_DAYS},\"mode\":\"first_seen\"}"
if cs_expect "7a Sofia switches the age gate to first_seen" 200; then
  if [ "$(cs_json '.mode')" = "first_seen" ] && [ "$(cs_json '.instance_locked')" = "false" ]; then
    cs_record "7b answer shows first_seen, still unlocked" PASS "mode=first_seen"
  else
    cs_record "7b answer shows first_seen, still unlocked" FAIL "got ${CS_BODY:0:300}"
  fi
fi
cs_http PUT "$AG" jwt:DATA_LEAD -H 'Content-Type: application/json' \
  -d "{\"enabled\":true,\"min_age_days\":${AG_DAYS},\"mode\":\"upstream_publish_time\"}"
cs_expect "7c Sofia switches it back to upstream_publish_time" 200
cs_http GET "$AG" jwt:DATA_LEAD
if [ "$(cs_json '.mode')" = "upstream_publish_time" ] && [ "$(cs_json '.instance_locked')" = "false" ] \
   && [ "$(cs_json '.min_age_days')" = "$AG_DAYS" ]; then
  cs_record "7d founding policy restored (${AG_DAYS} d, upstream_publish_time, unlocked)" PASS "HTTP ${CS_STATUS}"
else
  cs_record "7d founding policy restored (${AG_DAYS} d, upstream_publish_time, unlocked)" FAIL "HTTP ${CS_STATUS} ${CS_BODY:0:300}"
fi

# ---------------------------------------------------------------------------
# Task 8: Arjun uploads a minimal conda package to the conda local.
# Expected: 201 Created (conda.rs store_conda_package).
# ---------------------------------------------------------------------------
cpkg="${W}/conda-pkg"
mkdir -p "${cpkg}/info"
jq -n --arg n "$CONDA_NAME" --arg v "$ETL_VER" \
  '{name:$n,version:$v,build:"0",build_number:0,depends:[],subdir:"noarch",arch:null,platform:null,noarch:"generic",license:"MIT"}' \
  > "${cpkg}/info/index.json"
printf '{"paths": [], "paths_version": 1}\n' > "${cpkg}/info/paths.json"
(cd "$cpkg" && tar cjf "${W}/${CONDA_FILE}" info/)
CONDA_SHA=$(sha256sum "${W}/${CONDA_FILE}" | cut -d' ' -f1)
cs_http PUT "/conda/${HAL_REPO_DATA_CONDA_LOCAL}/noarch/${CONDA_FILE}" basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN \
  -H 'Content-Type: application/octet-stream' --data-binary "@${W}/${CONDA_FILE}"
cs_expect "8 Arjun uploads ${CONDA_FILE} to the conda local (personal token)" 201

# ---------------------------------------------------------------------------
# Task 9: the conda virtual's noarch repodata lists it (#4173), and the file
# downloads through the virtual with the same bytes.
# ---------------------------------------------------------------------------
cs_http GET "/conda/${HAL_REPO_DATA_CONDA}/noarch/repodata.json" basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN
if cs_expect "9 noarch/repodata.json through the conda virtual" 200; then
  if [ "$(jq -r --arg f "$CONDA_FILE" '(.packages[$f] // .["packages.conda"][$f] // {}) | .sha256 // empty' "$CS_BODY_FILE" 2>/dev/null)" = "$CONDA_SHA" ]; then
    cs_record "9b repodata lists ${CONDA_FILE} with its sha256" PASS "sha256 ${CONDA_SHA:0:16}..."
  else
    cs_expect_body "9b repodata lists ${CONDA_FILE}" "$CONDA_FILE"
  fi
fi
cs_http GET "/conda/${HAL_REPO_DATA_CONDA}/noarch/${CONDA_FILE}" basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN
if cs_expect "9c ${CONDA_FILE} downloads through the conda virtual" 200; then
  got=$(sha256sum "$CS_BODY_FILE" | cut -d' ' -f1)
  if [ "$got" = "$CONDA_SHA" ]; then
    cs_record "9d downloaded conda package is byte-identical" PASS "sha256 ${got:0:16}..."
  else
    cs_record "9d downloaded conda package is byte-identical" FAIL "uploaded ${CONDA_SHA}, got ${got}"
  fi
fi

# Optional real conda client: pixi from a local image, solving against the
# team's conda LOCAL channel (the virtual would pull all of conda-forge's
# repodata into a throwaway container).
ENGINE="$(command -v podman 2>/dev/null || command -v docker 2>/dev/null || true)"
if [ -n "${HAL_CONDA_CLIENT_IMAGE:-}" ] && [ -n "$ENGINE" ] \
   && "$ENGINE" image inspect "$HAL_CONDA_CLIENT_IMAGE" >/dev/null 2>&1; then
  CH=$(url_with_creds "${BASE_URL}/conda/${HAL_REPO_DATA_CONDA_LOCAL}" "$HAL_DATA_DEV_USER" "$HAL_DATA_DEV_TOKEN")
  if run_logged pixi "$ENGINE" run --rm --network host "$HAL_CONDA_CLIENT_IMAGE" \
       pixi exec --channel "$CH" --spec "${CONDA_NAME}==${ETL_VER}" -- true; then
    cs_record "9e pixi installs ${CONDA_NAME}==${ETL_VER} from the team channel" PASS "pixi exec ok"
  else
    cs_record "9e pixi installs ${CONDA_NAME}==${ETL_VER} from the team channel" FAIL "$(log_tail pixi)"
  fi
else
  cs_record "9e pixi installs ${CONDA_NAME} from the team channel" SKIP "set HAL_CONDA_CLIENT_IMAGE to a local image with pixi"
fi

# ---------------------------------------------------------------------------
# Task 10: an age gate on the conda remote cannot be enabled.
# Expected: 400 Validation (H/age_gate.rs:690-701; conda has no age_gate_spec,
# formats/mod.rs:503-617). The message lists "npm, pypi, and vscode ..., go,
# cargo" and omits maven and mcp, which are enforceable: stale text.
# ---------------------------------------------------------------------------
cs_http PUT "/api/v1/repositories/${HAL_REPO_DATA_CONDA_REMOTE}/age-gate" jwt:DATA_LEAD \
  -H 'Content-Type: application/json' -d '{"enabled":true,"min_age_days":7,"mode":"upstream_publish_time"}'
if cs_expect "10 Sofia cannot enable an age gate on the conda remote" 400; then
  # Pin the message the handler returns today (age_gate.rs:695-696): it names
  # conda's format and the formats it lists as enforceable. It is stale (no
  # maven, no mcp); if it changes, this check says so.
  msg=$(cs_json '.message // .error // empty')
  if printf '%s' "$msg" | grep -qi 'conda' && printf '%s' "$msg" | grep -qi 'npm' && printf '%s' "$msg" | grep -qi 'pypi'; then
    cs_record "10b 400 message names conda and the enforceable formats (age_gate.rs:695-696)" PASS \
      "$(printf '%s' "$msg" | cut -c1-160)$(printf '%s' "$msg" | grep -qi maven || echo '; omits maven and mcp (stale text)')"
  else
    cs_record "10b 400 message names conda and the enforceable formats (age_gate.rs:695-696)" FAIL \
      "message: $(printf '%s' "$msg" | cut -c1-200)" "${CS_BODY:0:400}"
  fi
fi

# ---------------------------------------------------------------------------
# Task 11: Sofia removes Arjun's sdist over REST.
# Expected: 409 "Cannot delete an immutable/released artifact". A PyPI
# package file is immutable (cache_classifier::classify_pypi) and only an
# instance admin may delete one (repositories.rs delete_blocked_by_immutability,
# called in delete_artifact after the delete-action gate). ROLES.md said 200;
# the code says 409 for a project admin who is not an instance admin.
# ---------------------------------------------------------------------------
ETL_PATH="${ETL_NAME}/${ETL_VER}/${ETL_SDIST}"
cs_http DELETE "/api/v1/repositories/${HAL_REPO_DATA_PYPI_LOCAL}/artifacts/${ETL_PATH}" jwt:DATA_LEAD
if cs_expect "11 Sofia (project admin) deletes Arjun's sdist: immutable package file (repositories.rs delete_blocked_by_immutability)" 409; then
  cs_expect_body "11b refusal says immutable" "immutable"
fi
cs_http GET "/pypi/${HAL_REPO_DATA_PYPI_LOCAL}/simple/${ETL_NAME}/" jwt:DATA_LEAD
cs_expect_body "11c sdist still served after the refused delete" "$ETL_SDIST"

# ---------------------------------------------------------------------------
# Things that should NOT work
# ---------------------------------------------------------------------------
# Arjun's personal token cannot read firmware (no grant -> 404, A:2724).
cs_http GET "/cargo/${HAL_REPO_FW_CARGO_LOCAL}/config.json" basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN
cs_expect "N1 Arjun's token cannot read the firmware cargo index (deny-by-hide)" 404

# Arjun deletes the day-0 package with his token: the scope check comes
# first (repositories.rs delete_artifact: require_scope("delete:artifacts")).
SEED_PATH="${HAL_SEED_PYPI}/${HAL_SEED_PYPI_VERSION}/${HAL_SEED_PYPI//-/_}-${HAL_SEED_PYPI_VERSION}.tar.gz"
cs_http DELETE "/api/v1/repositories/${HAL_REPO_DATA_PYPI_LOCAL}/artifacts/${SEED_PATH}" token:HAL_DATA_DEV_TOKEN
if cs_expect "N2 Arjun's token cannot delete the day-0 sdist" 403; then
  cs_expect_body "N2b refusal names the missing scope" "Token does not have required scope: delete:artifacts"
fi
cs_http GET "/pypi/${HAL_REPO_DATA_PYPI_LOCAL}/simple/${HAL_SEED_PYPI}/" basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN
cs_expect_body "N2c day-0 sdist still listed" "${HAL_SEED_PYPI//-/_}-${HAL_SEED_PYPI_VERSION}.tar.gz"

# Arjun (group read+write, not project admin) changes the age gate: 403
# (age_gate.rs authorize_repo_age_gate -> require_repo_admin).
cs_http PUT "$AG" jwt:DATA_DEV -H 'Content-Type: application/json' \
  -d "{\"enabled\":true,\"min_age_days\":1,\"mode\":\"first_seen\"}"
cs_expect "N3 Arjun (not project admin) cannot change the age gate" 403
cs_http GET "$AG" jwt:DATA_LEAD
if [ "$(cs_json '.min_age_days')" = "$AG_DAYS" ] && [ "$(cs_json '.mode')" = "upstream_publish_time" ]; then
  cs_record "N3b age gate unchanged after Arjun's refused write" PASS "min_age_days=${AG_DAYS}"
else
  cs_record "N3b age gate unchanged after Arjun's refused write" FAIL "${CS_BODY:0:300}"
fi

# The CI token's repository list deliberately omits the conda local
# (README "Tokens"): a write there answers 404 (A:3324-3335). The ci role owns
# the full CI matrix; data checks its own channel.
cs_http PUT "/conda/${HAL_REPO_DATA_CONDA_LOCAL}/noarch/${CONDA_NAME}-ci-${ETL_VER}-0.tar.bz2" token:HAL_CI_TOKEN \
  -H 'Content-Type: application/octet-stream' --data-binary "@${W}/${CONDA_FILE}"
cs_expect "N4 CI token cannot publish to the conda local (outside its repository list)" 404

cs_end
