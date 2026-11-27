#!/usr/bin/env bash
# =============================================================================
# tiers/promotion-chain-and-peer-push/oracle.sh (artifact-keeper#6546, #6549)
# =============================================================================
# See manifest for the bugs, the peer setup and the gates.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

SUF="$(echo "${RUN_ID##*-}" | tr 'A-Z_' 'a-z-' | tr -cd 'a-z0-9-' | tail -c 8)$$"
SLOT="$DTF_SLOT"
IMG="app"
DEV="pcdev-${SLOT}-${SUF}"     # docker staging
STAGE="pcstg-${SLOT}-${SUF}"   # docker local, push-subscribed
PROD="pcprd-${SLOT}-${SUF}"    # docker local
GSRC="pcgsrc-${SLOT}-${SUF}"   # generic staging
GREL="pcgrel-${SLOT}-${SUF}"   # generic local, push-subscribed

WORK="$(mktemp -d -t dtf-pc-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
AUTHZ=()
relogin() { auth_admin >/dev/null 2>&1; AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}"); }
call() { # METHOD PATH BODY OUT -> http code
  local c
  c="$(curl -s --max-time 60 -o "$4" -w '%{http_code}' -X "$1" "${AUTHZ[@]}" \
        -H 'Content-Type: application/json' ${3:+-d "$3"} "${BASE_URL}$2" 2>/dev/null)"
  echo "${c:-000}"
}
mkrepo() { # KEY FORMAT TYPE -> repository id
  call POST /api/v1/repositories \
    "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"$2\",\"repo_type\":\"$3\",\"is_public\":false}" "$WORK/mk.json" >/dev/null
  psql_q "SELECT id FROM repositories WHERE key = '$1'"
}
art_id() { # REPO PATH-LIKE -> live artifact id
  psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
          WHERE r.key = '$1' AND a.path LIKE '$2' AND NOT a.is_deleted ORDER BY a.created_at LIMIT 1"
}
push_rows() { # REPO PATH-LIKE -> queued push rows for PEER_ID
  psql_q "SELECT count(*) FROM sync_tasks st JOIN artifacts a ON a.id = st.artifact_id \
          JOIN repositories r ON r.id = a.repository_id \
          WHERE st.peer_instance_id = '${PEER_ID}' AND st.task_type = 'push' \
            AND r.key = '$1' AND a.path LIKE '$2' AND NOT a.is_deleted"
}
promote() { # SRC ARTIFACT_ID TARGET OUT -> http code
  call POST "/api/v1/promotion/repositories/$1/artifacts/$2/promote" "{\"target_repository\":\"$3\"}" "$4"
}
blob_push() { # REPO FILE -> http code
  local d; d="sha256:$(sha256sum "$2" | cut -d' ' -f1)"
  curl -s --max-time 60 -o /dev/null -w '%{http_code}' -X POST "${AUTHZ[@]}" \
    -H 'Content-Type: application/octet-stream' --data-binary "@$2" \
    "${BASE_URL}/v2/$1/${IMG}/blobs/uploads/?digest=${d}" 2>/dev/null
}
gen_put() { # REPO PATH -> http code
  printf 'dtf promotion-chain %s %s\n' "$2" "$(date +%s%N)" > "$WORK/g.bin"
  curl -s --max-time 60 -o /dev/null -w '%{http_code}' -X PUT "${AUTHZ[@]}" \
    --data-binary "@$WORK/g.bin" "${BASE_URL}/api/v1/repositories/$1/artifacts/$2" 2>/dev/null
}

begin_suite "promotion-chain-and-peer-push"
relogin

# =============================================================================
begin_test "SETUP: repositories, an image in dev, a push peer on stage and the generic release"
ERR=""
for spec in "$DEV:docker:staging" "$STAGE:docker:local" "$PROD:docker:local" \
            "$GSRC:generic:staging" "$GREL:generic:local"; do
  IFS=: read -r k f t <<<"$spec"
  [ -n "$(mkrepo "$k" "$f" "$t")" ] || ERR="${ERR} create ${k} failed;"
done

printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"dtf":"%s"}' "$SUF" > "$WORK/config.json"
printf 'dtf layer %s\n' "$SUF" | gzip -n > "$WORK/layer.tar.gz"
for f in config.json layer.tar.gz; do
  c="$(blob_push "$DEV" "$WORK/$f")"; [ "$c" = "201" ] || ERR="${ERR} blob ${f} -> ${c};"
done
jq -nc --arg cd "sha256:$(sha256sum "$WORK/config.json" | cut -d' ' -f1)" \
       --argjson cs "$(stat -c %s "$WORK/config.json" 2>/dev/null || stat -f %z "$WORK/config.json")" \
       --arg ld "sha256:$(sha256sum "$WORK/layer.tar.gz" | cut -d' ' -f1)" \
       --argjson ls "$(stat -c %s "$WORK/layer.tar.gz" 2>/dev/null || stat -f %z "$WORK/layer.tar.gz")" '{
  schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json",
  config: { mediaType: "application/vnd.oci.image.config.v1+json", digest: $cd, size: $cs },
  layers: [ { mediaType: "application/vnd.oci.image.layer.v1.tar+gzip", digest: $ld, size: $ls } ]
}' > "$WORK/manifest.json"
c="$(curl -s --max-time 60 -o /dev/null -w '%{http_code}' -X PUT "${AUTHZ[@]}" \
      -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@$WORK/manifest.json" \
      "${BASE_URL}/v2/${DEV}/${IMG}/manifests/1.0" 2>/dev/null)"
[ "$c" = "201" ] || ERR="${ERR} manifest PUT -> ${c};"
MAN_DIGEST="sha256:$(sha256sum "$WORK/manifest.json" | cut -d' ' -f1)"
MAN_DEV="$(psql_q "SELECT a.id FROM artifacts a WHERE a.repository_id = (SELECT id FROM repositories WHERE key = '${DEV}') \
           AND a.storage_key = 'oci-manifests/${MAN_DIGEST}' AND NOT a.is_deleted LIMIT 1")"
[ -n "$MAN_DEV" ] || ERR="${ERR} no manifest artifact row for ${MAN_DIGEST} in dev;"

PEER_ID="$(curl -sf --max-time 60 "${AUTHZ[@]}" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"dtf-pc-peer-${SLOT}-${SUF}\",\"endpoint_url\":\"http://dtf-pc-peer-${SLOT}-${SUF}.invalid:8080\",\"api_key\":\"dtf-${SUF}\"}" \
  "${BASE_URL}/api/v1/peers" 2>/dev/null | jq -r '.id // empty' 2>/dev/null)"
if [ -z "$PEER_ID" ]; then
  ERR="${ERR} peer registration failed;"
else
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "UPDATE peer_instances SET status = 'online', last_heartbeat_at = NOW(), \
     backoff_until = NOW() + INTERVAL '1 day' WHERE id = '${PEER_ID}'" >/dev/null 2>&1
  for k in "$STAGE" "$GREL"; do
    c="$(call POST "/api/v1/peers/${PEER_ID}/repositories" \
          "{\"repository_id\":\"$(psql_q "SELECT id FROM repositories WHERE key = '${k}'")\",\"sync_enabled\":true,\"replication_mode\":\"push\"}" "$WORK/sub.json")"
    [ "$c" = "200" ] || ERR="${ERR} subscribe ${k} -> ${c};"
  done
fi
for p in single.bin bulk-a.bin bulk-b.bin; do
  c="$(gen_put "$GSRC" "pc/${p}")"; case "$c" in 200|201) ;; *) ERR="${ERR} upload ${p} -> ${c};" ;; esac
done
if [ -z "$ERR" ]; then pass; else infra_fail "setup could not complete:${ERR}"; end_suite; exit $?; fi

# =============================================================================
begin_test "CONTROL: a plain upload to a push-subscribed generic repository queues a push row"
gen_put "$GREL" "pc/direct.bin" >/dev/null
n="$(push_rows "$GREL" 'pc/direct.bin')"
if [ "$n" = "1" ]; then pass; else fail "push rows for the direct upload: ${n:-?} (want 1)"; fi

# =============================================================================
c1="$(promote "$DEV" "$MAN_DEV" "$STAGE" "$WORK/hop1.json")"
begin_test "CONTROL #6546: the image promotes from dev (staging) to stage (local)"
MAN_STAGE="$(psql_q "SELECT a.id FROM artifacts a WHERE a.repository_id = (SELECT id FROM repositories WHERE key = '${STAGE}') \
             AND a.storage_key = 'oci-manifests/${MAN_DIGEST}' AND NOT a.is_deleted LIMIT 1")"
if [ "$c1" = "200" ] && [ -n "$MAN_STAGE" ]; then pass; else
  fail "dev -> stage: HTTP ${c1}, stage manifest row '${MAN_STAGE}': $(head -c 400 "$WORK/hop1.json")"
fi

c2="$(promote "$STAGE" "${MAN_STAGE:-x}" "$PROD" "$WORK/hop2.json")"
c3="$(curl -s --max-time 60 -o /dev/null -w '%{http_code}' "${AUTHZ[@]}" \
      -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
      "${BASE_URL}/v2/${PROD}/${IMG}/manifests/${MAN_DIGEST}" 2>/dev/null)"
begin_test "FIX #6546: the same image promotes on from stage to prod and prod serves it"
if [ "$c2" = "200" ] && [ "$c3" = "200" ]; then pass; else
  fail "stage -> prod: HTTP ${c2} ($(head -c 300 "$WORK/hop2.json")); GET prod manifest: ${c3}"
fi

# =============================================================================
begin_test "FIX #6549: the docker promotion into the push-subscribed stage queues a push row"
n="$(psql_q "SELECT count(*) FROM sync_tasks WHERE peer_instance_id = '${PEER_ID}' \
             AND task_type = 'push' AND artifact_id = '${MAN_STAGE:-00000000-0000-0000-0000-000000000000}'")"
if [ "$n" = "1" ]; then pass; else fail "push rows for the promoted manifest in stage: ${n:-?} (want 1)"; fi

c="$(promote "$GSRC" "$(art_id "$GSRC" 'pc/single.bin')" "$GREL" "$WORK/single.json")"
n="$(push_rows "$GREL" 'pc/single.bin')"
begin_test "FIX #6549: a single promotion into a push-subscribed repository queues a push row for the copy"
if [ "$c" = "200" ] && [ "$n" = "1" ]; then pass; else
  fail "single promote HTTP ${c}, push rows ${n:-?} (want 200 and 1): $(head -c 300 "$WORK/single.json")"
fi

c="$(call POST "/api/v1/promotion/repositories/${GSRC}/promote" \
      "{\"target_repository\":\"${GREL}\",\"artifact_ids\":[\"$(art_id "$GSRC" 'pc/bulk-a.bin')\",\"$(art_id "$GSRC" 'pc/bulk-b.bin')\"]}" \
      "$WORK/bulk.json")"
n="$(push_rows "$GREL" 'pc/bulk-%')"
begin_test "FIX #6549: a bulk promotion into a push-subscribed repository queues a push row per copy"
if [ "$c" = "200" ] && [ "$n" = "2" ]; then pass; else
  fail "bulk promote HTTP ${c}, push rows ${n:-?} (want 200 and 2): $(head -c 300 "$WORK/bulk.json")"
fi

end_suite
