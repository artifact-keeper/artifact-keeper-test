#!/usr/bin/env bash
# =============================================================================
# harness/lib/internet_fetch.sh — tell "the test client could not download its
# own tooling from the internet" apart from a product failure
# =============================================================================
# WHY THIS EXISTS
# The 1.12.1 candidate's dtf-advisory leg (artifact-keeper run 44244223519,
# heavy-topology) reported format-conformance as a product FAIL because the
# Maven client could not fetch maven-deploy-plugin from Maven Central:
#   No plugin found for prefix 'deploy' ... available from the repositories
#   [local (...), central (https://repo.maven.apache.org/maven2)]
# The candidate was never asked anything. A step that fails like that is an
# INFRA/SETUP failure (lib/exit_codes.sh, DTF_EXIT_INFRA) and should be
# recorded with infra_fail, like every other "the harness could not evaluate
# this" case, so dtf-advisory-outcome.sh retries it once and then warns.
#
#   dtf_internet_fetch_failure <log-file>
#       Exit 0 and print the first matching line when the log shows a client
#       failing to reach a PUBLIC host (Maven Central, PyPI, npmjs, GitHub
#       releases, the Debian/Ubuntu/Alpine mirrors, ...) or failing a DNS
#       lookup of a dotted public hostname. Exit 1 otherwise.
#
# Fail-safe direction, judged per LOG, not per line: if any line of the failed
# step's log names the candidate or a DTF-internal host (backend, backend-b,
# peer-backend, 127.0.0.1, localhost, BASE_URL's host, any *.local such as
# tf.dtf.local or ldap.dtf.local) next to an error, or carries a server error
# body (JSON "error"/"message"/"detail") that quotes a public host, i.e. the
# candidate's own upstream failure, the step is a FAIL. An HTTP answer from a
# public host (404, a checksum mismatch) is not a network failure either. So a
# real product failure is not relabeled; at worst an unrecognized network
# error stays a FAIL, which is what it was before.
# =============================================================================

# Hosts test clients download tooling from. Matched as substrings of the line.
DTF_PUBLIC_HOSTS_RE='repo\.maven\.apache\.org|repo1\.maven\.org|plugins\.gradle\.org|services\.gradle\.org|pypi\.org|files\.pythonhosted\.org|registry\.npmjs\.org|registry\.yarnpkg\.com|github\.com|githubusercontent\.com|deb\.debian\.org|security\.debian\.org|archive\.ubuntu\.com|security\.ubuntu\.com|ports\.ubuntu\.com|dl-cdn\.alpinelinux\.org|proxy\.golang\.org|sum\.golang\.org|crates\.io|rubygems\.org|api\.nuget\.org|packagist\.org|anaconda\.(org|com)|r-project\.org|cocoapods\.org|pub\.dev|registry\.terraform\.io|releases\.hashicorp\.com|get\.helm\.sh|dl\.k8s\.io'

# Network-failure wording of the clients the DTF runs (mvn, pip, npm, apt,
# apk, curl, git, go, cargo, ...), plus Maven's "plugin could not be resolved".
DTF_NET_FAIL_RE='No plugin found for prefix|Could not transfer|Could not resolve|Failed to read artifact descriptor|could not be resolved|Could not resolve host|Temporary failure (in name resolution|resolving)|Name or service not known|getaddrinfo|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ECONNRESET|ECONNREFUSED|Connection (timed out|refused|reset)|Network is unreachable|Failed to establish a new connection|Max retries exceeded|Read timed out|ReadTimeoutError|Failed to fetch|unable to access|TLS handshake timeout|i/o timeout|no such host|network error|temporary error'

# A DNS failure for a dotted name. Internal dotted names (*.local: the
# tf.dtf.local / ldap.dtf.local / bsr.dtf.local aliases) are the candidate's
# side and are ruled out by the per-log guard before this is tried.
DTF_DNS_FAIL_RE="(Could not resolve host: |Temporary failure resolving '|getaddrinfo (ENOTFOUND|EAI_AGAIN) |dial tcp: lookup )[A-Za-z0-9-]+\.[A-Za-z0-9.-]+"

# An HTTP answer is not a network failure: the host was reached.
DTF_HTTP_ANSWER_RE='Could not find artifact|was not found in|status code: 4[0-9][0-9]|[Cc]hecksum|EINTEGRITY|E40[0-9]| 404'

# The candidate and the hosts beside it. 127.0.0.1 is anchored so Docker's
# embedded resolver 127.0.0.11:53 (Go: "lookup X on 127.0.0.11:53: no such
# host") is not mistaken for the candidate.
DTF_INTERNAL_HOSTS_RE='[a-z0-9-]*backend[a-z0-9-]*|127\.0\.0\.1([^0-9]|$)|localhost|[A-Za-z0-9.-]+\.local([^A-Za-z0-9.-]|$)'

# Words that make a line about the candidate an error line.
DTF_ERRORISH_RE="[Ee]rror|ERR|[Ff]ail|[Ff]atal|refused|reset|timed out|[Tt]imeout|status code|HTTP/[0-9.]+ [45][0-9][0-9]|(^|[^0-9])[45][0-9][0-9]([^0-9]|$)|Could not|[Uu]nable|no such host|${DTF_NET_FAIL_RE}"

# A server's error body (JSON), as a client prints what the candidate sent.
DTF_SERVER_BODY_RE='"(error|errors|message|detail|reason)"[[:space:]]*:'

dtf_internet_fetch_failure() {
  local log="$1" internal="$DTF_INTERNAL_HOSTS_RE" host line
  [ -s "$log" ] || return 1
  host="${BASE_URL:-}"; host="${host#*://}"; host="${host%%/*}"; host="${host%%:*}"
  [ -n "$host" ] && internal="${internal}|${host//./\\.}([^A-Za-z0-9.-]|$)"
  # Per-log guard: the candidate (or a host beside it) next to an error, or
  # the candidate's error body quoting an upstream, anywhere in the log.
  grep -E -- "$internal" "$log" | grep -Eq -- "$DTF_ERRORISH_RE" && return 1
  grep -E -- "$DTF_SERVER_BODY_RE" "$log" | grep -Eq -- "$DTF_PUBLIC_HOSTS_RE" && return 1
  line="$(grep -Ev -- "$DTF_HTTP_ANSWER_RE" "$log" | grep -E -- "$DTF_NET_FAIL_RE" | grep -E -m 1 -- "$DTF_PUBLIC_HOSTS_RE")"
  [ -n "$line" ] || line="$(grep -Ev -- "$DTF_HTTP_ANSWER_RE" "$log" | grep -E -m 1 -- "$DTF_DNS_FAIL_RE")"
  [ -n "$line" ] || return 1
  printf '%s\n' "$line" | sed 's/^[[:space:]]*//' | cut -c1-300
}
