# =============================================================================
# plugins/maven.sh — format-conformance plugin
# FC_FORMAT: maven
# FC_MOUNT: maven
# FC_REPO_FORMAT: maven
# FC_PROFILE: client.maven
# FC_SERVICE: client-maven
# FC_ENABLED: 1
# =============================================================================
# Ports the proven corpus tests/formats/test-maven-native-client.sh verbs
# (mvn deploy:deploy-file :175, mvn dependency:get :235) onto the DTF topology.
# The verbs are already green on the k8s release gate; this moves them so future
# thread x format work (s3 / upgrade x mvn) reuses the same consume commands
# (kept parameterized on $FC_INT_URL, never hardcoding the repo type).
#
# Maven routes (backend handlers/maven.rs): nest /maven; single wildcard
# `GET|PUT /:repo_key/*path`. The resolver FOLLOWS the advertised GAV layout
# (`group/artifact/version/artifact-version.jar`) + `maven-metadata.xml` and
# verifies the `.sha1` sidecars — the #2580 (advertised location) / #2183
# (SNAPSHOT timestamp metadata) classes that upload-only curl tests cannot see.
#
# The consume runs `mvn dependency:get` into an EMPTY local repo so the fetch is
# a REAL network resolution against AK only (remoteRepositories=dtf::...::AK).
# =============================================================================
FC_CASES="snapshot_metadata checksum_strict gav_case"

MVN_GROUP="io.dtf"
MVN_ARTIFACT="marker"
MVN_VER="1.0.0"
MVN_GROUP_PATH="io/dtf"                       # dotted groupId -> directory layout
MVN_MARKER_TOKEN="DTF-MAVEN-INSTALLED-${MVN_VER}"

# All work lives under a container /tmp workspace; the container is fresh per
# stack so a fixed path is safe and keeps the exec scripts readable.
MVN_WS="/tmp/dtf-maven"
MVN_SETTINGS="${MVN_WS}/settings.xml"

# Emit a hermetic settings.xml into the container. Maven 3.8.1+ ships the
# `maven-default-http-blocker` mirror (mirrorOf=external:http:*) that refuses any
# plain-HTTP repository; the cluster-internal backend is plain HTTP. We override
# it with our own mirror capturing the `dtf` repo id with <blocked>false</blocked>
# (user mirrors evaluate before the built-in blocker), and give both ids matching
# <server> credentials (Maven looks up auth by the RESOLVED mirror id). This is
# exactly the corpus native-client override, ported.
_mvn_write_settings() {
  local local_repo="$1"
  nc_exec "mkdir -p '${MVN_WS}' '${local_repo}' && cat > '${MVN_SETTINGS}' <<EOF
<settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\">
  <localRepository>${local_repo}</localRepository>
  <mirrors>
    <mirror>
      <id>dtf-allow-http</id>
      <name>Allow plain-HTTP for the cluster-internal AK repo</name>
      <url>${FC_INT_URL}</url>
      <mirrorOf>dtf</mirrorOf>
      <blocked>false</blocked>
    </mirror>
  </mirrors>
  <servers>
    <server><id>dtf</id><username>${ADMIN_USER}</username><password>${ADMIN_PASS}</password></server>
    <server><id>dtf-allow-http</id><username>${ADMIN_USER}</username><password>${ADMIN_PASS}</password></server>
  </servers>
</settings>
EOF"
}

# ---------------------------------------------------------------------------
# fc_publish — assemble a synthetic marker JAR + POM inside the container and
# `mvn deploy:deploy-file` them to the hosted AK repo (a REAL Maven publish;
# the corpus proves this verb). Writes the deploy-side settings too.
# ---------------------------------------------------------------------------
fc_publish() {
  nc_exec 'command -v mvn >/dev/null 2>&1 && mvn -v | head -1' \
    || { echo "mvn missing inside the provisioned maven client"; return 1; }

  local deploy_repo="${MVN_WS}/.m2-deploy"
  _mvn_write_settings "$deploy_repo" || return 1

  # Build the marker JAR (a jar is just a zip; the marker file proves the
  # resolved bytes are the ones we published) + a matching POM.
  nc_exec "set -e
mkdir -p '${MVN_WS}/jar/META-INF' '${MVN_WS}/jar/dtf'
printf '%s\n' '${MVN_MARKER_TOKEN}' > '${MVN_WS}/jar/dtf/marker.txt'
cat > '${MVN_WS}/jar/META-INF/MANIFEST.MF' <<EOF
Manifest-Version: 1.0
Created-By: dtf-format-conformance
Implementation-Title: ${MVN_ARTIFACT}
Implementation-Version: ${MVN_VER}
EOF
( cd '${MVN_WS}/jar' && jar cfm '${MVN_WS}/${MVN_ARTIFACT}-${MVN_VER}.jar' META-INF/MANIFEST.MF dtf )
cat > '${MVN_WS}/${MVN_ARTIFACT}-${MVN_VER}.pom' <<EOF
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<project xmlns=\"http://maven.apache.org/POM/4.0.0\">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${MVN_GROUP}</groupId>
  <artifactId>${MVN_ARTIFACT}</artifactId>
  <version>${MVN_VER}</version>
  <packaging>jar</packaging>
</project>
EOF
test -s '${MVN_WS}/${MVN_ARTIFACT}-${MVN_VER}.jar'" || { echo "jar/pom assembly failed"; return 1; }

  # Record the published jar sha for the client-side byte-identity proof.
  MVN_PUB_SHA="$(nc_sha256_in_ctr "${MVN_WS}/${MVN_ARTIFACT}-${MVN_VER}.jar")"
  echo "  published jar sha256=${MVN_PUB_SHA}"

  nc_exec -t 300 "mvn -B -q --settings '${MVN_SETTINGS}' deploy:deploy-file \
    -Dfile='${MVN_WS}/${MVN_ARTIFACT}-${MVN_VER}.jar' \
    -DpomFile='${MVN_WS}/${MVN_ARTIFACT}-${MVN_VER}.pom' \
    -DrepositoryId=dtf -Durl='${FC_INT_URL}'" \
    || { echo "mvn deploy:deploy-file failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_client_setup — verify mvn is present and write a FRESH-local-repo settings
# for the pull side (empty local repo forces a real network fetch from AK).
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec 'command -v mvn >/dev/null 2>&1' \
    || { echo "mvn missing inside the provisioned maven client"; return 1; }
  # Wipe any pull-side local repo so consume is a real resolution, not a cache hit.
  nc_exec "rm -rf '${MVN_WS}/.m2-pull' && mkdir -p '${MVN_WS}/.m2-pull'" || return 1
  _mvn_write_settings "${MVN_WS}/.m2-pull" || return 1
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. `mvn dependency:get` into the empty pull repo
# resolves the GAV path + maven-metadata.xml + checksums from AK ONLY.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 300 "mvn -B -q --settings '${MVN_SETTINGS}' dependency:get \
    -DremoteRepositories='dtf::default::${FC_INT_URL}' \
    -Dartifact='${MVN_GROUP}:${MVN_ARTIFACT}:${MVN_VER}' \
    -Dtransitive=false" \
    || { echo "mvn dependency:get failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the jar landed in the pull-side local repo,
# its bytes are byte-identical to what we deployed, and the marker is inside.
# ---------------------------------------------------------------------------
fc_assert() {
  local jar="${MVN_WS}/.m2-pull/${MVN_GROUP_PATH}/${MVN_ARTIFACT}/${MVN_VER}/${MVN_ARTIFACT}-${MVN_VER}.jar"
  nc_exec "test -s '${jar}'" || { echo "resolved jar missing at ${jar}"; return 1; }
  local pull_sha
  pull_sha="$(nc_sha256_in_ctr "$jar")"
  nc_assert_sha_eq "$MVN_PUB_SHA" "$pull_sha" "resolved jar != deployed jar" || return 1
  # And the marker inside the resolved jar is the one we published (use the JDK
  # `jar` tool — the maven image ships no `unzip`).
  nc_exec "cd '${MVN_WS}' && rm -rf verify && mkdir verify && cd verify && \
jar xf '${jar}' && grep -q '${MVN_MARKER_TOKEN}' dtf/marker.txt" \
    || { echo "marker token not found inside the resolved jar"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — #2580 discriminator. maven-metadata.xml advertises the
# version; the GAV-layout jar URL resolves (200) while the flat (non-GAV) shape
# a naive client might emit 404s.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local ver
  ver="$(nc_advertised "${FC_URL}/${MVN_GROUP_PATH}/${MVN_ARTIFACT}/maven-metadata.xml" \
    "grep -oE '<version>[^<]+</version>' | sed -E 's:</?version>::g' | head -1")" || return 1
  echo "  maven-metadata.xml advertises version=${ver}"
  case "$ver" in "$MVN_VER") : ;; *) echo "  metadata version mismatch (wanted ${MVN_VER})"; return 1 ;; esac
  # positive: the advertised GAV jar path resolves
  nc_expect_code 200 "${FC_URL}/${MVN_GROUP_PATH}/${MVN_ARTIFACT}/${MVN_VER}/${MVN_ARTIFACT}-${MVN_VER}.jar" || return 1
  # negative: a flat (non-GAV) shape must NOT resolve
  nc_expect_code 404 "${FC_URL}/${MVN_ARTIFACT}-${MVN_VER}.jar" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# snapshot_metadata (#2183 class) — deploy 1.1-SNAPSHOT TWICE; the timestamped
# version-level maven-metadata.xml must resolve the LATEST snapshot, and the
# resolver (which fetches the .sha1 sidecar) must fetch bytes matching that xml.
# Bug class: SNAPSHOT metadata drift (stale/mismatched timestamp resolution).
fc_case_snapshot_metadata() {
  local sver="1.1-SNAPSHOT"
  local sjar="${MVN_WS}/${MVN_ARTIFACT}-snap.jar"
  local i
  # two distinct deploys -> two timestamped members under the same SNAPSHOT dir
  for i in 1 2; do
    nc_exec "printf 'DTF-MAVEN-SNAP-${i}\n' > '${MVN_WS}/snap-marker.txt' && \
mkdir -p '${MVN_WS}/snapjar/dtf' && cp '${MVN_WS}/snap-marker.txt' '${MVN_WS}/snapjar/dtf/marker.txt' && \
( cd '${MVN_WS}/snapjar' && jar cf '${sjar}' dtf )" || return 1
    nc_exec -t 300 "mvn -B -q --settings '${MVN_SETTINGS}' deploy:deploy-file \
      -Dfile='${sjar}' -DgroupId='${MVN_GROUP}' -DartifactId='${MVN_ARTIFACT}' \
      -Dversion='${sver}' -Dpackaging=jar -DrepositoryId=dtf -Durl='${FC_INT_URL}'" \
      || { echo "snapshot deploy ${i} failed"; return 1; }
  done
  # version-level metadata must advertise a timestamp + buildNumber
  local meta="${WORK_DIR}/snap-meta.xml"
  nc_fetch "${FC_URL}/${MVN_GROUP_PATH}/${MVN_ARTIFACT}/${sver}/maven-metadata.xml" "$meta" || return 1
  grep -q '<timestamp>' "$meta" || { echo "SNAPSHOT metadata missing <timestamp>"; head -40 "$meta"; return 1; }
  local ts bn
  ts="$(grep -oE '<timestamp>[^<]+</timestamp>' "$meta" | sed -E 's:</?timestamp>::g' | head -1)"
  bn="$(grep -oE '<buildNumber>[^<]+</buildNumber>' "$meta" | sed -E 's:</?buildNumber>::g' | head -1)"
  echo "  SNAPSHOT resolves to timestamp=${ts} buildNumber=${bn}"
  [ -n "$ts" ] || { echo "empty snapshot timestamp"; return 1; }
  # the advertised timestamped jar must resolve, AND its .sha1 sidecar must
  # match the served jar bytes (the #2183 checksum-vs-bytes proof).
  local base="${MVN_ARTIFACT}-1.1-${ts}-${bn}"
  local tj="${WORK_DIR}/snap.jar" ts1="${WORK_DIR}/snap.jar.sha1"
  nc_fetch "${FC_URL}/${MVN_GROUP_PATH}/${MVN_ARTIFACT}/${sver}/${base}.jar"      "$tj"  || return 1
  nc_fetch "${FC_URL}/${MVN_GROUP_PATH}/${MVN_ARTIFACT}/${sver}/${base}.jar.sha1" "$ts1" || return 1
  [ -s "$tj" ] || { echo "timestamped snapshot jar did not resolve (${base}.jar)"; return 1; }
  local served_sha1 adv_sha1
  served_sha1="$(sha1sum "$tj" | awk '{print $1}')"
  adv_sha1="$(tr -d ' \n\r\t' < "$ts1")"
  nc_assert_sha_eq "$adv_sha1" "$served_sha1" "advertised .sha1 != served snapshot jar bytes" || return 1
}

# checksum_strict — resolve with Maven's strict checksum policy (`-C`), which
# fails the build on ANY checksum mismatch. A green resolve proves the stored
# .sha1 sidecars are correct for every resolved artifact (jar + pom).
# Bug class: incorrect/absent checksum sidecars (silent corruption).
fc_case_checksum_strict() {
  nc_exec "rm -rf '${MVN_WS}/.m2-strict' && mkdir -p '${MVN_WS}/.m2-strict'" || return 1
  _mvn_write_settings "${MVN_WS}/.m2-strict" || return 1
  nc_exec -t 300 "mvn -B -q -C --settings '${MVN_SETTINGS}' dependency:get \
    -DremoteRepositories='dtf::default::${FC_INT_URL}' \
    -Dartifact='${MVN_GROUP}:${MVN_ARTIFACT}:${MVN_VER}' -Dtransitive=false" \
    || { echo "strict-checksum resolve failed (stored .sha1 sidecars are wrong)"; return 1; }
  echo "  strict (-C) resolve succeeded: stored .sha1 sidecars verify"
}

# gav_case — a dotted groupId with an extra segment (io.dtf.sub) must round-trip
# through the dots->dirs layout mapping: deploy then resolve into an empty repo.
# Bug class: groupId dot-segment mishandling in the path layout.
fc_case_gav_case() {
  local g="io.dtf.sub" gp="io/dtf/sub" a="submarker" v="2.0.0"
  nc_exec "mkdir -p '${MVN_WS}/subjar/dtf' && printf 'DTF-MAVEN-SUB\n' > '${MVN_WS}/subjar/dtf/marker.txt' && \
( cd '${MVN_WS}/subjar' && jar cf '${MVN_WS}/${a}-${v}.jar' dtf )" || return 1
  nc_exec -t 300 "mvn -B -q --settings '${MVN_SETTINGS}' deploy:deploy-file \
    -Dfile='${MVN_WS}/${a}-${v}.jar' -DgroupId='${g}' -DartifactId='${a}' \
    -Dversion='${v}' -Dpackaging=jar -DrepositoryId=dtf -Durl='${FC_INT_URL}'" \
    || { echo "dotted-groupId deploy failed"; return 1; }
  # positive: the dotted groupId maps to the nested dir layout and resolves
  nc_expect_code 200 "${FC_URL}/${gp}/${a}/${v}/${a}-${v}.jar" || return 1
  nc_exec "rm -rf '${MVN_WS}/.m2-sub' && mkdir -p '${MVN_WS}/.m2-sub'" || return 1
  _mvn_write_settings "${MVN_WS}/.m2-sub" || return 1
  nc_exec -t 300 "mvn -B -q --settings '${MVN_SETTINGS}' dependency:get \
    -DremoteRepositories='dtf::default::${FC_INT_URL}' \
    -Dartifact='${g}:${a}:${v}' -Dtransitive=false" \
    || { echo "dotted-groupId resolve failed"; return 1; }
  local rj="${MVN_WS}/.m2-sub/${gp}/${a}/${v}/${a}-${v}.jar"
  nc_exec "test -s '${rj}'" || { echo "dotted-groupId jar not in local repo at ${rj}"; return 1; }
  echo "  io.dtf.sub round-trips through the dots->dirs layout"
}
