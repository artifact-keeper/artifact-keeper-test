# =============================================================================
# plugins/pypi.sh — format-conformance plugin (pypi)
# FC_FORMAT: pypi
# FC_MOUNT: pypi
# FC_REPO_FORMAT: pypi
# FC_PROFILE: client.pypi
# FC_SERVICE: client-pypi
# FC_ENABLED: 1
# =============================================================================
# pypi routes (backend handlers/pypi.rs): nest /pypi; twine upload
# `POST /:repo/`; simple index `GET /:repo/simple/` + `GET /:repo/simple/:proj/`;
# download `GET /:repo/simple/:proj/:filename`. The simple-index page advertises
# each file as `<a href="...whl#sha256=<hex>">` — the location a real client
# FOLLOWS (and whose #sha256 fragment pip verifies).
#
# Consume via the advertised path: `pip install --index-url .../simple/
# --only-binary=:all: dtf-marker` reads the simple index, resolves the wheel
# href, verifies the #sha256 fragment, downloads + installs the marker module.
# --index-url (no --extra) + an empty cache => AK is the ONLY source.
#
# Edge cases (game-plan §4.18): PEP 503 normalized names (`Dtf.Marker` ->
# `dtf-marker`) resolve the same project; the `#sha256=` fragment equals the
# served wheel bytes.
#
# HELD OUT of FC_CASES: `yanking` (PEP 592) — see the case's own header. The
# corpus's tests/formats/test-pypi-yanking.sh (0 hits in release-gate.yml) tests
# a feature the backend does not implement AT ALL: handlers/pypi.rs declares only
# upload / simple_root / simple_project / download, and the string "yank" appears
# nowhere in it (only cargo.rs implements yank). Wiring it as an active gate case
# would assert an unbuilt feature — that is a feature request, not coverage — so
# it is registered and implemented but not enabled, exactly as apk.sh does with
# `signed_index`. Enabling it is a one-line FC_CASES edit the day PEP 592 ships.
# =============================================================================
FC_CASES="normalized_name sha256_fragment"

PYPI_DIST="dtf-marker"                 # PEP 503 canonical (normalized) name
PYPI_MOD="dtf_marker"                  # importable module
PYPI_VER="1.0.0"
PYPI_WHEEL="${PYPI_MOD}-${PYPI_VER}-py3-none-any.whl"
PYPI_MARKER_TOKEN="DTF-PYPI-INSTALLED-${PYPI_VER}"
TWINE_VERSION="6.0.1"

# ---------------------------------------------------------------------------
# fc_publish — install the build/upload toolchain (rig egress, proven by the
# dnf leg), build a real wheel, and `twine upload` it via the REAL client.
# ---------------------------------------------------------------------------
fc_publish() {
  nc_exec 'command -v python3 >/dev/null 2>&1 && python3 --version && command -v pip >/dev/null 2>&1' \
    || { echo "python3/pip missing inside the provisioned pypi client"; return 1; }
  nc_exec -t 300 "pip install --quiet --disable-pip-version-check \
    'twine==${TWINE_VERSION}' 'build==1.2.2' 'setuptools==75.6.0' 'wheel==0.45.1' 2>&1" \
    || { echo "toolchain install failed"; return 1; }
  nc_exec "rm -rf /tmp/pub && mkdir -p /tmp/pub/src/${PYPI_MOD} && cd /tmp/pub
cat > pyproject.toml <<EOF
[build-system]
requires = [\"setuptools>=61\", \"wheel\"]
build-backend = \"setuptools.build_meta\"

[project]
name = \"${PYPI_DIST}\"
version = \"${PYPI_VER}\"
description = \"DTF format-conformance marker package\"
requires-python = \">=3.7\"
EOF
printf 'MARKER = \"%s\"\n' '${PYPI_MARKER_TOKEN}' > src/${PYPI_MOD}/__init__.py" || return 1
  nc_exec -t 240 "cd /tmp/pub && python3 -m build --wheel --no-isolation 2>&1" || return 1
  nc_exec -t 180 "cd /tmp/pub && TWINE_USERNAME='${ADMIN_USER}' TWINE_PASSWORD='${ADMIN_PASS}' \
    twine upload --disable-progress-bar --non-interactive \
    --repository-url '${FC_INT_URL}/' dist/*.whl 2>&1" \
    || { echo "twine upload failed"; return 1; }
  # Advertised simple index must now list the project (host-side).
  nc_expect_code 200 "${FC_URL}/simple/${PYPI_DIST}/" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — write a pip.conf INSIDE the container pointing ONLY at the
# AK simple index (no PyPI fallback) + a fresh consume dir. Reads are
# authenticated (the pypi read routes require auth even on public repos), so the
# index URL embeds URL-encoded admin creds — the ONLY source, no fallback.
# ---------------------------------------------------------------------------
fc_client_setup() {
  # URL-encode the password (may contain `!`, etc.) for the userinfo component.
  PYPI_PW_ENC="$(printf '%s' "${ADMIN_PASS}" | jq -sRr @uri)"
  PYPI_AUTH_INDEX="http://${ADMIN_USER}:${PYPI_PW_ENC}@backend:8080/pypi/${FC_REPO}/simple/"
  nc_exec "rm -rf /tmp/consume /tmp/pipcache && mkdir -p /tmp/consume /root
cat > /root/pip.conf <<EOF
[global]
trusted-host = backend
cache-dir = /tmp/pipcache
EOF
cat /root/pip.conf" || return 1
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. `pip install --only-binary=:all:` reads the
# simple index, resolves + verifies the wheel href, and installs it into a fresh
# target dir. --index-url (only AK) + empty cache => AK is the ONLY source.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 240 "PIP_CONFIG_FILE=/root/pip.conf pip install \
    --index-url '${PYPI_AUTH_INDEX}' --trusted-host backend --only-binary=:all: --no-cache-dir \
    --target /tmp/consume/site '${PYPI_DIST}==${PYPI_VER}' 2>&1" \
    || { echo "pip install failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the marker module imports from the installed
# target and exposes the token, and pip recorded the dist-info.
# ---------------------------------------------------------------------------
fc_assert() {
  nc_exec "test -d /tmp/consume/site/${PYPI_MOD} && \
PYTHONPATH=/tmp/consume/site python3 -c 'import ${PYPI_MOD}; print(${PYPI_MOD}.MARKER)' \
  | grep -q '${PYPI_MARKER_TOKEN}' && \
ls /tmp/consume/site | grep -E '${PYPI_MOD}-${PYPI_VER}\.dist-info'" \
    || { echo "marker module not importable / dist-info missing"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2580 discriminator. The simple index advertises the
# wheel href; it resolves (200) while the project-less shape (a client emitting
# a truncated href) 404s.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local href path wheel
  href="$(nc_advertised "${FC_URL}/simple/${PYPI_DIST}/" \
    "grep -oE 'href=\"[^\"]*\\.whl[^\"]*\"' | head -1 | sed -E 's/href=\"([^\"]*)\"/\\1/'")" || return 1
  echo "  advertised href=${href}"
  path="${href%%#*}"
  path="$(printf '%s' "$path" | sed -E 's#^https?://[^/]+##')"
  nc_expect_code 200 "${BASE_URL}${path}" || return 1
  wheel="$(basename "$path")"
  # project-less shape must NOT resolve (simple index requires the project dir)
  nc_expect_code 404 "${FC_URL}/simple/${wheel}" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# normalized_name — PEP 503: `Dtf.Marker`, `dtf_marker`, `dtf-marker` are the
# SAME project. The simple index must resolve every non-canonical form to the
# canonical project; a genuinely-unknown project must 404. Bug class: name
# normalization drift (a client requesting the non-canonical form gets a miss).
fc_case_normalized_name() {
  local n
  for n in "Dtf.Marker" "dtf_marker" "DTF--Marker"; do
    nc_expect_code 200 "${FC_URL}/simple/${n}/" || {
      echo "  non-canonical form '${n}' did not resolve to the project"; return 1; }
  done
  echo "  all non-canonical name forms resolve to the canonical project"
  # negative: an unrelated project must 404, not fall open
  nc_expect_code 404 "${FC_URL}/simple/no-such-dtf-project/" || {
    echo "  unknown project did not 404 (fall-open)"; return 1; }
}

# sha256_fragment — the simple-index href carries `#sha256=<hex>`; pip pins the
# download against it. That hex MUST equal the sha256 of the served wheel bytes.
# Bug class: advertised-hash vs served-bytes drift (a mismatch fails pip).
fc_case_sha256_fragment() {
  local href frag path dl served
  href="$(nc_advertised "${FC_URL}/simple/${PYPI_DIST}/" \
    "grep -oE 'href=\"[^\"]*\\.whl[^\"]*\"' | head -1 | sed -E 's/href=\"([^\"]*)\"/\\1/'")" || return 1
  case "$href" in
    *'#sha256='*) : ;;
    *) echo "  href carries no #sha256 fragment: ${href}"; return 1 ;;
  esac
  frag="${href#*#sha256=}"
  path="${href%%#*}"
  path="$(printf '%s' "$path" | sed -E 's#^https?://[^/]+##')"
  dl="${WORK_DIR}/served-${PYPI_WHEEL}"
  nc_fetch "${BASE_URL}${path}" "$dl" || return 1
  served="$(nc_sha256 "$dl")"
  nc_assert_sha_eq "$frag" "$served" "#sha256 fragment != served-bytes sha256" || return 1
}

# ---------------------------------------------------------------------------
# yanking — HELD OUT of FC_CASES (see the header). PEP 592: a yanked release
# stays installable by exact pin but is skipped by ordinary resolution, and the
# simple index marks its files `data-yanked`.
#
# The corpus's test-pypi-yanking.sh probes three candidate yank endpoints and
# falls into `skip_suite "yank not implemented"` when all three miss — which is
# what would happen today on every backend: handlers/pypi.rs has NO yank route
# (verified at source; only cargo.rs implements yank). Rather than ship a
# permanently-red case for an unbuilt feature, this is kept implemented and
# disabled so the day PEP 592 lands the real-client proof is one line away.
#
# When enabling: this asserts the POSITIVE (yanked file still resolves by exact
# pin) AND the NEGATIVE (the index marks it data-yanked, and an unpinned resolve
# prefers the non-yanked version) — never just "the endpoint returned 2xx".
# ---------------------------------------------------------------------------
fc_case_yanking() {
  local yver="1.0.1"
  local ywheel="${PYPI_MOD}-${yver}-py3-none-any.whl"

  # publish a second version to yank
  nc_exec "cd /tmp/pub && sed -i 's/^version = .*/version = \"${yver}\"/' pyproject.toml" || return 1
  nc_exec -t 240 "cd /tmp/pub && rm -rf dist && python3 -m build --wheel --no-isolation 2>&1" || return 1
  nc_exec -t 180 "cd /tmp/pub && TWINE_USERNAME='${ADMIN_USER}' TWINE_PASSWORD='${ADMIN_PASS}' \
    twine upload --disable-progress-bar --non-interactive \
    --repository-url '${FC_INT_URL}/' dist/*.whl 2>&1" \
    || { echo "publish of ${yver} failed"; return 1; }

  # yank it (twine-style :action=yank multipart POST against the upload route)
  local code
  code="$(curl -s -o "${WORK_DIR}/yank.out" -w '%{http_code}' --max-time 60 \
    -X POST -H "$(format_auth_header)" \
    -F ":action=yank" -F "name=${PYPI_DIST}" -F "version=${yver}" \
    -F "reason=dtf format-conformance yank case" \
    "${FC_URL}/" 2>/dev/null)"
  echo "  POST :action=yank -> HTTP ${code}"
  case "$code" in
    200|201|204) : ;;
    *) echo "  yank endpoint not available (HTTP ${code}); PEP 592 unimplemented"
       head -c 200 "${WORK_DIR}/yank.out" 2>/dev/null; return 1 ;;
  esac

  # POSITIVE: the simple index marks the yanked file data-yanked
  local idx="${WORK_DIR}/simple-yank.html"
  nc_fetch "${FC_URL}/simple/${PYPI_DIST}/" "$idx" || return 1
  grep -qE "${ywheel}[^>]*data-yanked" "$idx" \
    || { echo "  ${ywheel} is not marked data-yanked in the simple index"; head -c 400 "$idx"; return 1; }
  echo "  simple index marks ${ywheel} data-yanked"

  # NEGATIVE: the yanked version must STILL be installable by exact pin (PEP 592
  # requires the file stay served), while an unpinned install must NOT select it.
  nc_exec -t 240 "pip install --quiet --no-cache-dir --force-reinstall \
    --index-url '${PYPI_AUTH_INDEX}' '${PYPI_DIST}==${yver}' 2>&1" \
    || { echo "  exact-pin install of the yanked version failed (PEP 592 requires it stay installable)"; return 1; }
  nc_exec -t 240 "pip install --quiet --no-cache-dir --force-reinstall \
    --index-url '${PYPI_AUTH_INDEX}' '${PYPI_DIST}' 2>&1" || return 1
  local got
  got="$(nc_exec "pip show ${PYPI_DIST} 2>/dev/null | awk '/^Version:/{print \$2}'")"
  echo "  unpinned resolve selected: ${got} (must not be the yanked ${yver})"
  [ "$got" != "$yver" ] || { echo "  unpinned resolution selected the YANKED version"; return 1; }
}
