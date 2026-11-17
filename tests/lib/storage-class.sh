# shellcheck shell=bash
# tests/lib/storage-class.sh - the StorageClass every throwaway test install
# puts its PVCs on (artifact-keeper/artifact-keeper#6081).
#
# Why this exists
# ---------------
# rocky's default StorageClass `local-path` keeps its volumes under
# /opt/local-path-provisioner on the node's 70G root filesystem, which also
# carries production. The gate and the self-tests leave ~24G of test-namespace
# PVCs there at a time. `local-path-home` is the same rancher.io/local-path
# provisioner with its volumes under /home/local-path-provisioner (1.8T), and
# is not the default (artifact-keeper-arc-runners#27). Every helm install of
# the chart into a test-* / smoke-* namespace asks for it explicitly here.
#
# The chart has no working global storageClass (`global.storageClass` in
# values.yaml is read by no template), so each component's key is set.
#
# Configuration
# -------------
#   AK_TEST_STORAGE_CLASS  unset  -> local-path-home
#                          a name -> that StorageClass
#                          empty  -> set nothing; the cluster's default class
#                                    (use this on kind/microk8s/local clusters)
#
# Usage (after the helm command array is built):
#   # shellcheck source=../tests/lib/storage-class.sh
#   source "${REPO_ROOT}/tests/lib/storage-class.sh"
#   ak_test_storage_class_append HELM_CMD || exit 1

AK_TEST_STORAGE_CLASS_DEFAULT="local-path-home"

# Every chart value that names the StorageClass of a PVC the chart creates
# (artifact-keeper-iac charts/artifact-keeper/templates: backend-pvc.yaml
# storage + scan-workspace + shared-config, backend-deployment.yaml ephemeral
# storage, postgres-statefulset.yaml, opensearch-deployment.yaml (PVC and
# StatefulSet volumeClaimTemplates), trivy-deployment.yaml,
# dtrack-deployment.yaml, image-builder.yaml). Keys an older chart does not
# know are ignored by helm, so chart-upgrade-smoke's previous chart is fine.
AK_TEST_STORAGE_CLASS_KEYS=(
  backend.persistence.storageClass
  backend.persistence.ephemeral.storageClass
  backend.sharedConfig.storageClass
  postgres.persistence.storageClass
  opensearch.persistence.storageClass
  trivy.persistence.storageClass
  dependencyTrack.persistence.storageClass
  imageBuilder.persistence.storageClass
)

# ak_test_storage_class: print the resolved class name (may be empty).
ak_test_storage_class() {
  printf '%s' "${AK_TEST_STORAGE_CLASS-$AK_TEST_STORAGE_CLASS_DEFAULT}"
}

# ak_test_storage_class_append ARRAY_NAME: append one --set-string per key to
# the named helm argument array. Returns 1 (with a message) when the cluster
# answers that the class does not exist, so a missing class fails the deploy
# at once instead of leaving every PVC Pending until the helm --wait timeout.
# Any other kubectl error (no RBAC on storageclasses, no kubectl) only warns:
# helm still applies the setting.
ak_test_storage_class_append() {
  local -n _ak_sc_args="$1"
  local sc out key
  sc="$(ak_test_storage_class)"
  if [ -z "$sc" ]; then
    echo "  StorageClass: cluster default (AK_TEST_STORAGE_CLASS is empty)"
    return 0
  fi
  if command -v kubectl >/dev/null 2>&1; then
    if ! out="$(kubectl get storageclass "$sc" -o name 2>&1)"; then
      if grep -q 'NotFound' <<<"$out"; then
        echo "ERROR: StorageClass '${sc}' does not exist on this cluster." >&2
        echo "  Create it (rocky: artifact-keeper-arc-runners cluster/storageclass-local-path-home.yaml)," >&2
        echo "  or set AK_TEST_STORAGE_CLASS to another class, or to empty for the cluster default." >&2
        return 1
      fi
      echo "  WARN: could not look up StorageClass '${sc}' (${out}); setting it anyway" >&2
    fi
  fi
  echo "  StorageClass for every PVC: ${sc}"
  for key in "${AK_TEST_STORAGE_CLASS_KEYS[@]}"; do
    _ak_sc_args+=(--set-string "${key}=${sc}")
  done
}
