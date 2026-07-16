# =============================================================================
# plugins/maven.sh — isolation-formats plugin (Thread 1 REGRESSION BASELINE)
# SEC_FORMAT: maven
# SEC_MOUNT: maven
# SEC_REPO_FORMAT: maven
# SEC_PROFILE:
# SEC_SERVICE:
# SEC_ENABLED: 1
# SEC_FLATKEY: 1
# =============================================================================
# The CORRECTNESS GATE for the whole generalization. Maven carries the
# #2504/#2574/#2584 read-attribution fix (services/maven_flat_attribution.rs),
# so a CORRECT oracle must report Maven isolation HOLDS (green) even though its
# storage key IS flat/repo-less (SEC_FLATKEY=1 — the white-box probe confirms the
# bare `maven/{path}` key; the runtime isolation comes from the attribution
# table, NOT from the key shape). If the driver ever reports Maven leaking, the
# driver is wrong, not the backend.
#
# The plant/read use the driver DEFAULTS (a plain authenticated curl PUT/GET of
# the object bytes to the GAV coordinate) — the exact mechanism prove.sh uses.
# This plugin therefore only supplies the three format-specific bits: the GAV
# collision coordinate, the object bytes, and the Maven attribution-table strip
# for the row-less F leg.
#
# Maven route (handlers/maven.rs): nest /maven; `PUT|GET /:repo_key/*path`.
# storage key = `maven/{path}` (maven.rs:2792) — repo-LESS.

# sec_coord — the GAV .jar path. $SEC_TAG makes A/B, C, and F distinct coords
# (distinct version segments) so the scenarios never interfere. The version dir
# and the `<artifactId>-<version>.jar` filename must agree or the write
# validators 400 (prove.sh's version-match note), so both embed the tag+suffix.
sec_coord() {
  local v="1.0-${SEC_TAG}-${SEC_SUF}"
  echo "com/dtf/isol/${v}/isol-${v}.jar"
}

# sec_secret_bytes — a minimal jar (zip magic `PK\x03\x04`) with the recognizable
# marker appended so the write validator accepts+stores it and a cross-tenant
# leak is byte-detectable by grep. This is prove.sh's row-less .jar fixture shape.
sec_secret_bytes() { printf 'PK\003\004%s' "$SEC_MARK"; }

# sec_owner_strip <repo_key> <coord> — the Maven-specific half of the row-less
# fixture: after the driver deletes the `artifacts` rows, also drop the
# per-key attribution rows so the physical object survives genuinely
# unattributed (the pristine #2574/#2584 legacy state).
sec_owner_strip() {
  local coord="$2"
  _sec_psql "DELETE FROM maven_flat_object_owner WHERE storage_key = 'maven/${coord}';" >/dev/null 2>&1 || true
}
