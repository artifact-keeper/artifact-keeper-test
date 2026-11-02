#!/usr/bin/env bash
# =============================================================================
# tiers/image-inspect-repository-scope/oracle.sh
#   artifact-keeper#5096 (PR #5098): image-inspect and base-info resolve a digest
#   only within the requested repository and image.
#   artifact-keeper#5111 (PR #5112): they read a config or provenance blob only
#   when the requested repository records it.
# See the manifest for the topology and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, RELEASE_GATE=1, JUNIT_OUTPUT_DIR,
# COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

setup_workdir
W="$WORK_DIR"
SUF="${RUN_ID##*-}-$$"
PRIV="dtf-insp-priv-${SUF}"
PUB="dtf-insp-pub-${SUF}"
MT='application/vnd.oci.image.manifest.v1+json'
IT='application/vnd.oci.image.index.v1+json'
OCI_AUTH=(-u "admin:${ADMIN_PASS}")
PRIV_MARK="private-marker-${SUF}"
PUB_MARK="public-marker-${SUF}"
PRIV_DOCKERFILE="FROM scratch # ${PRIV_MARK}"
PUB_DOCKERFILE="FROM scratch # ${PUB_MARK}"
ABSENT="sha256:$(printf 'absent-%s' "$SUF" | sha256sum | awk '{print $1}')"

sha_of() { sha256sum "$1" | awk '{print $1}'; }
size_of() { wc -c < "$1" | tr -d ' '; }
digest_of() { echo "sha256:$(sha_of "$1")"; }

# --- OCI pushes over /v2 with curl-built documents ---------------------------
push_blob() { # <repo> <image> <file>; records a failure in ERR
  local c
  c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 "${OCI_AUTH[@]}" -X POST \
    -H 'Content-Type: application/octet-stream' --data-binary "@$3" \
    "${BASE_URL}/v2/$1/$2/blobs/uploads/?digest=$(digest_of "$3")" 2>/dev/null || echo 000)"
  [ "$c" = "201" ] || ERR="${ERR} blob $3 into $1/$2=HTTP${c};"
}
push_manifest() { # <repo> <image> <reference> <media type> <file>
  local c
  c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 "${OCI_AUTH[@]}" -X PUT \
    -H "Content-Type: $4" --data-binary "@$5" \
    "${BASE_URL}/v2/$1/$2/manifests/$3" 2>/dev/null || echo 000)"
  [ "$c" = "201" ] || ERR="${ERR} manifest $1/$2:$3=HTTP${c};"
}
make_config() { # <file> <marker>
  jq -nc --arg m "$2" '{architecture:"amd64",os:"linux",
    config:{Env:["MARKER=\($m)"],User:$m},
    rootfs:{type:"layers",diff_ids:[]},
    history:[{created_by:"RUN true # \($m)"}]}' > "$1"
}
make_manifest() { # <out> <config digest> <config size> <layer file> [annotation]
  jq -nc --arg cd "$2" --argjson cs "$3" --arg ld "$(digest_of "$4")" --argjson ls "$(size_of "$4")" --arg note "${5:-}" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",
      config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$cd,size:$cs},
      layers:[{mediaType:"application/vnd.oci.image.layer.v1.tar",digest:$ld,size:$ls}]}
     + (if $note != "" then {annotations:{"dtf.note":$note}} else {} end)' \
    | tr -d '\n' > "$1"
}
make_index() { # <out> <child digest>
  jq -nc --arg d "$2" '{schemaVersion:2,mediaType:"application/vnd.oci.image.index.v1+json",
    manifests:[{mediaType:"application/vnd.oci.image.manifest.v1+json",digest:$d,size:10,
                platform:{architecture:"amd64",os:"linux"}}]}' | tr -d '\n' > "$1"
}
make_provenance() { # <out> <dockerfile text>
  jq -nc --arg d "$(printf '%s' "$2" | base64 | tr -d '\n')" \
    '{predicateType:"https://slsa.dev/provenance/v1",
      predicate:{runDetails:{builder:{id:"dtf"},metadata:{buildkit_metadata:{source:{infos:[{filename:"Dockerfile",data:$d}]}}}}}}' > "$1"
}
make_attestation() { # <out> <attestation config file> <provenance file>
  jq -nc --arg cd "$(digest_of "$2")" --argjson cs "$(size_of "$2")" \
    --arg pd "$(digest_of "$3")" --argjson ps "$(size_of "$3")" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",
      config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$cd,size:$cs},
      layers:[{mediaType:"application/vnd.in-toto+json",digest:$pd,size:$ps}]}' | tr -d '\n' > "$1"
}
make_attested_index() { # <out> <image digest> <attestation digest>
  jq -nc --arg i "$2" --arg a "$3" '{schemaVersion:2,mediaType:"application/vnd.oci.image.index.v1+json",
    manifests:[
      {mediaType:"application/vnd.oci.image.manifest.v1+json",digest:$i,size:10,platform:{architecture:"amd64",os:"linux"}},
      {mediaType:"application/vnd.oci.image.manifest.v1+json",digest:$a,size:10,platform:{architecture:"unknown",os:"unknown"},
       annotations:{"vnd.docker.reference.type":"attestation-manifest","vnd.docker.reference.digest":$i}}]}' \
    | tr -d '\n' > "$1"
}

# --- The reads under test (anonymous unless curl args add a token) -----------
INSPECT_BODY="$W/inspect.json"
inspect() { # <repo> <image> <reference> [curl args...] -> HTTP code, body in $INSPECT_BODY
  local repo="$1" image="$2" reference="$3"; shift 3
  : > "$INSPECT_BODY"
  curl -s -o "$INSPECT_BODY" -w '%{http_code}' --max-time 30 -G "$@" \
    --data-urlencode "image=${image}" --data-urlencode "reference=${reference}" \
    "${BASE_URL}/api/v1/repositories/${repo}/image-inspect" 2>/dev/null || echo 000
}
base_info() { # <repo> <image ref as a spec names it> -> "<HTTP> <found> <digest>"
  local c
  c="$(curl -s -o "$W/base.json" -w '%{http_code}' --max-time 30 -G \
    --data-urlencode "image=$2" \
    "${BASE_URL}/api/v1/repositories/$1/image-builds/base-info" 2>/dev/null || echo 000)"
  echo "$c $(jq -r '.found' "$W/base.json" 2>/dev/null) $(jq -r '.digest // "-"' "$W/base.json" 2>/dev/null)"
}
# Hex is masked so bodies that differ only in the digest they echo compare equal.
masked() { sed -E 's/[0-9a-f]{64}/<hex>/g' "$1" 2>/dev/null || true; }
snip() { head -c 400 "$INSPECT_BODY" 2>/dev/null | tr -d '\n' || true; }
marker_in() { jq -r '.config.env.MARKER // empty' "$INSPECT_BODY" 2>/dev/null || true; }
no_private() { ! grep -q "$PRIV_MARK" "$INSPECT_BODY" 2>/dev/null; }

# expect_refused <label> <repo> <image> <reference>: 404, no private marker.
expect_refused() {
  local st
  st="$(inspect "$2" "$3" "$4")"
  begin_test "$1"
  if [ "$st" = "404" ] && no_private; then pass
  else fail "expected 404 with no private content, got HTTP ${st}" "$(snip)"; fi
}
# expect_described <label> <repo> <image> <reference> <marker>: 200 with marker.
expect_described() {
  local st got
  st="$(inspect "$2" "$3" "$4")"; got="$(marker_in)"
  begin_test "$1"
  if [ "$st" = "200" ] && [ "$got" = "$5" ]; then pass
  else fail "expected 200 describing '$5', got HTTP ${st} marker '${got}'" "$(snip)"; fi
}
expect_not_found_info() { # <label> <repo> <image ref>
  local got
  got="$(base_info "$2" "$3")"
  begin_test "$1"
  if [ "${got%% *}" = "200" ] && [ "$(jq -r '.found' "$W/base.json" 2>/dev/null)" = "false" ] \
     && ! grep -q "$PRIV_MARK" "$W/base.json" 2>/dev/null; then pass
  else fail "expected 200 found:false, got ${got}" "$(head -c 400 "$W/base.json" 2>/dev/null)"; fi
}

begin_suite "image-inspect-repository-scope"

# =============================================================================
# Setup
# =============================================================================
begin_test "setup: admin login, a private and a public docker repository on the shared bucket"
TOK="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jq -r '.access_token // empty' 2>/dev/null || true)"
if [ -z "$TOK" ]; then infra_fail "admin login failed at ${BASE_URL}"; end_suite; fi
make_repo() { # <key> <is_public> -> key of the created repository
  curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/repositories" -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$1" --argjson p "$2" '{key:$k,name:$k,format:"docker",repo_type:"local",is_public:$p}')" \
    | jq -r '.key // empty' 2>/dev/null || true
}
if [ "$(make_repo "$PRIV" false)" != "$PRIV" ] || [ "$(make_repo "$PUB" true)" != "$PUB" ]; then
  infra_fail "could not create the docker repositories"; end_suite
fi
cleanup_repos() {
  curl -s -o /dev/null --max-time 30 -X DELETE -H "Authorization: Bearer ${TOK}" "${BASE_URL}/api/v1/repositories/${PRIV}" || true
  curl -s -o /dev/null --max-time 30 -X DELETE -H "Authorization: Bearer ${TOK}" "${BASE_URL}/api/v1/repositories/${PUB}" || true
}
add_exit_handler "cleanup_repos"
pass

begin_test "setup: images, indexes and attestations pushed"
ERR=""
printf 'dtf-insp-layer-%s\n' "$SUF" > "$W/layer"

# Private repository: team/app:v1 (image + config), team/app:multi (index over a
# second image, which is reached only through the index), and the provenance
# blob the forged attestation below borrows.
make_config "$W/priv.cfg" "$PRIV_MARK"
make_manifest "$W/priv.man" "$(digest_of "$W/priv.cfg")" "$(size_of "$W/priv.cfg")" "$W/layer"
make_config "$W/privchild.cfg" "${PRIV_MARK}-child"
make_manifest "$W/privchild.man" "$(digest_of "$W/privchild.cfg")" "$(size_of "$W/privchild.cfg")" "$W/layer"
make_index "$W/privindex.man" "$(digest_of "$W/privchild.man")"
make_provenance "$W/priv.prov" "$PRIV_DOCKERFILE"
for f in priv.cfg privchild.cfg layer priv.prov; do push_blob "$PRIV" team/app "$W/$f"; done
push_manifest "$PRIV" team/app v1 "$MT" "$W/priv.man"
push_manifest "$PRIV" team/app "$(digest_of "$W/privchild.man")" "$MT" "$W/privchild.man"
push_manifest "$PRIV" team/app multi "$IT" "$W/privindex.man"
PRIV_DIGEST="$(digest_of "$W/priv.man")"
PRIV_CHILD="$(digest_of "$W/privchild.man")"

# Public repository: team/app:v1 and other/thing:v1, each with its own config.
make_config "$W/pub.cfg" "$PUB_MARK"
make_manifest "$W/pub.man" "$(digest_of "$W/pub.cfg")" "$(size_of "$W/pub.cfg")" "$W/layer"
make_config "$W/other.cfg" "${PUB_MARK}-other"
make_manifest "$W/other.man" "$(digest_of "$W/other.cfg")" "$(size_of "$W/other.cfg")" "$W/layer"
for f in pub.cfg layer; do push_blob "$PUB" team/app "$W/$f"; done
for f in other.cfg layer; do push_blob "$PUB" other/thing "$W/$f"; done
push_manifest "$PUB" team/app v1 "$MT" "$W/pub.man"
push_manifest "$PUB" other/thing v1 "$MT" "$W/other.man"
PUB_DIGEST="$(digest_of "$W/pub.man")"
OTHER_DIGEST="$(digest_of "$W/other.man")"

# Public: team/app:multi, an index over a platform child of its own.
make_config "$W/pubchild.cfg" "${PUB_MARK}-child"
make_manifest "$W/pubchild.man" "$(digest_of "$W/pubchild.cfg")" "$(size_of "$W/pubchild.cfg")" "$W/layer"
make_index "$W/pubindex.man" "$(digest_of "$W/pubchild.man")"
push_blob "$PUB" team/app "$W/pubchild.cfg"
push_manifest "$PUB" team/app "$(digest_of "$W/pubchild.man")" "$MT" "$W/pubchild.man"
push_manifest "$PUB" team/app multi "$IT" "$W/pubindex.man"
PUB_INDEX="$(digest_of "$W/pubindex.man")"
PUB_CHILD="$(digest_of "$W/pubchild.man")"

# #5096: team/app:forged, an index pushed into the public repository that lists
# the private child (a manifest the public repository does not hold).
make_index "$W/forged.man" "$PRIV_CHILD"
push_manifest "$PUB" team/app forged "$IT" "$W/forged.man"

# #5111: team/app:borrowed names the private config, team/app:missing names a
# config stored nowhere. Neither blob is recorded for the public repository.
# The annotation keeps borrowed's bytes (so its digest) different from the
# private image's own manifest, which names the same config and layer.
make_manifest "$W/borrowed.man" "$(digest_of "$W/priv.cfg")" "$(size_of "$W/priv.cfg")" "$W/layer" borrowed
printf 'config-stored-nowhere-%s' "$SUF" > "$W/nowhere.cfg"
make_manifest "$W/missing.man" "$(digest_of "$W/nowhere.cfg")" "$(size_of "$W/nowhere.cfg")" "$W/layer"
push_manifest "$PUB" team/app borrowed "$MT" "$W/borrowed.man"
push_manifest "$PUB" team/app missing "$MT" "$W/missing.man"
BORROWED_DIGEST="$(digest_of "$W/borrowed.man")"
MISSING_DIGEST="$(digest_of "$W/missing.man")"

# #5111: two attested indexes over the public image. The provenance blob of
# attested-own is recorded for the public repository, attested-foreign names the
# private repository's.
printf '{"attestation-config":"%s"}' "$SUF" > "$W/att.cfg"
push_blob "$PUB" team/app "$W/att.cfg"
make_provenance "$W/pub.prov" "$PUB_DOCKERFILE"
push_blob "$PUB" team/app "$W/pub.prov"
make_attestation "$W/att-own.man" "$W/att.cfg" "$W/pub.prov"
make_attestation "$W/att-foreign.man" "$W/att.cfg" "$W/priv.prov"
push_manifest "$PUB" team/app "$(digest_of "$W/att-own.man")" "$MT" "$W/att-own.man"
push_manifest "$PUB" team/app "$(digest_of "$W/att-foreign.man")" "$MT" "$W/att-foreign.man"
make_attested_index "$W/attested-own.man" "$PUB_DIGEST" "$(digest_of "$W/att-own.man")"
make_attested_index "$W/attested-foreign.man" "$PUB_DIGEST" "$(digest_of "$W/att-foreign.man")"
push_manifest "$PUB" team/app attested-own "$IT" "$W/attested-own.man"
push_manifest "$PUB" team/app attested-foreign "$IT" "$W/attested-foreign.man"
if [ -z "$ERR" ]; then pass; else infra_fail "push failed:${ERR}"; end_suite; fi

# =============================================================================
# Controls: what must keep resolving
# =============================================================================
expect_described "CONTROL: public team/app by tag" "$PUB" team/app v1 "$PUB_MARK"
expect_described "CONTROL: public team/app by its own digest" "$PUB" team/app "$PUB_DIGEST" "$PUB_MARK"
expect_described "CONTROL: public other/thing by its own digest" "$PUB" other/thing "$OTHER_DIGEST" "${PUB_MARK}-other"
expect_described "CONTROL: an index by tag describes its platform child" "$PUB" team/app multi "${PUB_MARK}-child"
expect_described "CONTROL: an index by digest describes its platform child" "$PUB" team/app "$PUB_INDEX" "${PUB_MARK}-child"
expect_described "CONTROL: a platform child by its digest under the index's image" "$PUB" team/app "$PUB_CHILD" "${PUB_MARK}-child"

begin_test "CONTROL: the admin reads the private image on its own repository"
st="$(inspect "$PRIV" team/app "$PRIV_DIGEST" -H "Authorization: Bearer ${TOK}")"; got="$(marker_in)"
if [ "$st" = "200" ] && [ "$got" = "$PRIV_MARK" ]; then pass
else fail "HTTP ${st} marker '${got}', want 200 '${PRIV_MARK}'" "$(snip)"; fi

begin_test "CONTROL: an attestation whose provenance blob the repository records returns the Dockerfile"
st="$(inspect "$PUB" team/app attested-own)"
if [ "$st" = "200" ] && grep -qF "$PUB_DOCKERFILE" "$INSPECT_BODY" 2>/dev/null; then pass
else fail "HTTP ${st}, want 200 with the public Dockerfile in provenance" "$(snip)"; fi

begin_test "CONTROL: a digest that exists nowhere is 404"
st="$(inspect "$PUB" team/app "$ABSENT")"; cp "$INSPECT_BODY" "$W/absent.json"
if [ "$st" = "404" ]; then pass; else fail "HTTP ${st}, want 404" "$(snip)"; fi

begin_test "CONTROL: base-info finds the public image by tag and by digest"
a="$(base_info "$PUB" "${PUB}/team/app:v1")"; b="$(base_info "$PUB" "${PUB}/team/app@${PUB_DIGEST}")"
if [ "$a" = "200 true ${PUB_DIGEST}" ] && [ "$b" = "200 true ${PUB_DIGEST}" ]; then pass
else fail "tag '${a}', digest '${b}', want 200 true ${PUB_DIGEST}"; fi

# =============================================================================
# FIX #5096: a digest resolves only within the requested repository and image
# =============================================================================
begin_test "FIX #5096: a private digest under the public repository is 404, identical to an absent digest"
st="$(inspect "$PUB" team/app "$PRIV_DIGEST")"
if [ "$st" = "404" ] && no_private && [ "$(masked "$INSPECT_BODY")" = "$(masked "$W/absent.json")" ]; then pass
else fail "HTTP ${st}, want a 404 equal to the absent digest's ('$(masked "$W/absent.json")')" "$(snip)"; fi

expect_not_found_info "FIX #5096: base-info of the private digest under the public repository is found:false" \
  "$PUB" "${PUB}/team/app@${PRIV_DIGEST}"
expect_refused "FIX #5096: a private index child under the public repository is 404" "$PUB" team/app "$PRIV_CHILD"
expect_not_found_info "FIX #5096: base-info of the private index child under the public repository is found:false" \
  "$PUB" "${PUB}/team/app@${PRIV_CHILD}"

expect_refused "FIX #5096: an index pushed into the public repository listing the private child is 404 by tag" \
  "$PUB" team/app forged
expect_refused "FIX #5096: the same index by digest is 404" "$PUB" team/app "$(digest_of "$W/forged.man")"
expect_not_found_info "FIX #5096: base-info of that index is found:false" "$PUB" "${PUB}/team/app:forged"

expect_refused "FIX #5096: a digest of other/thing under team/app in the same repository is 404" \
  "$PUB" team/app "$OTHER_DIGEST"
expect_refused "FIX #5096: a digest of team/app under other/thing in the same repository is 404" \
  "$PUB" other/thing "$PUB_DIGEST"
expect_not_found_info "FIX #5096: base-info of another image's digest in the same repository is found:false" \
  "$PUB" "${PUB}/other/thing@${PUB_DIGEST}"
expect_refused "FIX #5096: a platform child under an image whose index does not list it is 404" \
  "$PUB" other/thing "$PUB_CHILD"

# =============================================================================
# FIX #5111: a config or provenance blob is read only when the repository
# records it
# =============================================================================
st_miss="$(inspect "$PUB" team/app missing)"; cp "$INSPECT_BODY" "$W/missing.json"
begin_test "CONTROL: a manifest naming a config stored nowhere is 404"
if [ "$st_miss" = "404" ]; then pass; else fail "HTTP ${st_miss}, want 404" "$(snip)"; fi

begin_test "FIX #5111: a manifest naming the private config is 404 by tag, identical to a config stored nowhere"
st="$(inspect "$PUB" team/app borrowed)"
if [ "$st" = "404" ] && no_private && [ "$(masked "$INSPECT_BODY")" = "$(masked "$W/missing.json")" ]; then pass
else fail "HTTP ${st}, want a 404 equal to '$(masked "$W/missing.json")'" "$(snip)"; fi

begin_test "FIX #5111: the same manifest by digest is 404, identical to a config stored nowhere by digest"
st_m="$(inspect "$PUB" team/app "$MISSING_DIGEST")"; cp "$INSPECT_BODY" "$W/missing-d.json"
st="$(inspect "$PUB" team/app "$BORROWED_DIGEST")"
if [ "$st" = "404" ] && [ "$st_m" = "404" ] && no_private \
   && [ "$(masked "$INSPECT_BODY")" = "$(masked "$W/missing-d.json")" ]; then pass
else fail "HTTP ${st} (stored-nowhere: ${st_m}), want equal 404s" "$(snip)"; fi

expect_not_found_info "FIX #5111: base-info of the manifest naming the private config is found:false (tag)" \
  "$PUB" "${PUB}/team/app:borrowed"
expect_not_found_info "FIX #5111: base-info of the manifest naming the private config is found:false (digest)" \
  "$PUB" "${PUB}/team/app@${BORROWED_DIGEST}"

begin_test "FIX #5111: an attestation naming the private provenance blob resolves without provenance"
st="$(inspect "$PUB" team/app attested-foreign)"; prov="$(jq -c '.provenance // empty' "$INSPECT_BODY" 2>/dev/null || true)"
if [ "$st" = "200" ] && [ -z "$prov" ] && no_private && [ "$(marker_in)" = "$PUB_MARK" ]; then pass
else fail "HTTP ${st} provenance '${prov:0:300}', want 200 with no provenance and no private content" "$(snip)"; fi

end_suite
