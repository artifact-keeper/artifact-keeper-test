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
#       lookup of any dotted hostname. Exit 1 otherwise.
#
# Fail-safe direction: a line that mentions the candidate (backend:,
# 127.0.0.1, localhost, BASE_URL's host) never counts, and an HTTP answer
# from a public host (404, a checksum mismatch) is not a network failure. So a
# real product failure is not relabeled; at worst an unrecognized network
# error stays a FAIL, which is what it was before.
# =============================================================================

# Hosts test clients download tooling from. Matched as substrings of the line.
DTF_PUBLIC_HOSTS_RE='repo\.maven\.apache\.org|repo1\.maven\.org|plugins\.gradle\.org|services\.gradle\.org|pypi\.org|files\.pythonhosted\.org|registry\.npmjs\.org|registry\.yarnpkg\.com|github\.com|githubusercontent\.com|deb\.debian\.org|security\.debian\.org|archive\.ubuntu\.com|security\.ubuntu\.com|ports\.ubuntu\.com|dl-cdn\.alpinelinux\.org|proxy\.golang\.org|sum\.golang\.org|crates\.io|rubygems\.org|api\.nuget\.org|packagist\.org|anaconda\.(org|com)|r-project\.org|cocoapods\.org|pub\.dev|registry\.terraform\.io|releases\.hashicorp\.com|get\.helm\.sh|dl\.k8s\.io'

# Network-failure wording of the clients the DTF runs (mvn, pip, npm, apt,
# apk, curl, git, go, cargo, ...), plus Maven's "plugin could not be resolved".
DTF_NET_FAIL_RE='No plugin found for prefix|Could not transfer|Could not resolve|Failed to read artifact descriptor|could not be resolved|Could not resolve host|Temporary failure (in name resolution|resolving)|Name or service not known|getaddrinfo|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ECONNRESET|ECONNREFUSED|Connection (timed out|refused|reset)|Network is unreachable|Failed to establish a new connection|Max retries exceeded|Read timed out|ReadTimeoutError|Failed to fetch|unable to access|TLS handshake timeout|i/o timeout|no such host|network error|temporary error'

# A DNS failure for any dotted name is the internet: compose service names
# (backend, ldap, client-maven, ...) have no dot.
DTF_DNS_FAIL_RE="(Could not resolve host: |Temporary failure resolving '|getaddrinfo (ENOTFOUND|EAI_AGAIN) |dial tcp: lookup )[A-Za-z0-9-]+\.[A-Za-z0-9.-]+"

# An HTTP answer is not a network failure: the host was reached.
DTF_HTTP_ANSWER_RE='Could not find artifact|was not found in|status code: 4[0-9][0-9]|[Cc]hecksum|EINTEGRITY|E40[0-9]| 404'

dtf_internet_fetch_failure() {
  local log="$1" own='backend:|127\.0\.0\.1|localhost' host line
  [ -s "$log" ] || return 1
  host="${BASE_URL:-}"; host="${host#*://}"; host="${host%%/*}"; host="${host%%:*}"
  [ -n "$host" ] && own="${own}|${host//./\\.}"
  # Lines dropped before matching: anything about the candidate, and answers.
  own="${own}|${DTF_HTTP_ANSWER_RE}"
  line="$(grep -Ev -- "$own" "$log" | grep -E -- "$DTF_NET_FAIL_RE" | grep -E -m 1 -- "$DTF_PUBLIC_HOSTS_RE")"
  [ -n "$line" ] || line="$(grep -Ev -- "$own" "$log" | grep -E -m 1 -- "$DTF_DNS_FAIL_RE")"
  [ -n "$line" ] || return 1
  printf '%s\n' "$line" | sed 's/^[[:space:]]*//' | cut -c1-300
}
