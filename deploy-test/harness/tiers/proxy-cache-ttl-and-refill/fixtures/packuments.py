#!/usr/bin/env python3
# =============================================================================
# packuments.py - npm packuments for the proxy-cache-ttl-and-refill age-gate
# cases (artifact-keeper#4431, #4432). Prints one packument as JSON.
#
#   packuments.py mixed  <name> <upstream>   the 45 version keys of
#       confusing-browser-globals (numeric and hash prereleases of one core),
#       all published 2020-01-01, latest 1.0.11. A short list goes through
#       insertion sort, which never checks the comparator, so the full list is
#       what made the pre-fix sort_by panic (#4431).
#   packuments.py keep   <name> <upstream>   1.0.0, 1.1.0, 2.0.0-beta.1
#       published 2020, 1.2.0 published now; latest 1.1.0 (allowed), next
#       2.0.0-beta.1 (#4432: the publisher's latest survives).
#   packuments.py repoint <name> <upstream>  the same versions, latest 1.2.0
#       (young, so the gate removes it: #4432 repoints latest to the newest
#       allowed RELEASE at or below it, 1.1.0, not the newer prerelease).
# =============================================================================
import datetime
import json
import sys

MIXED = (
    "0.0.0 1.0.1 1.0.2 1.0.3 1.0.4 1.0.5 1.0.5-next.9b4009d7 1.0.5-next.c662dfb0 "
    "1.0.6 1.0.6-next.6a95aae9 1.0.7 1.0.8 1.0.9 1.0.10 1.0.11 1.1.0-next.14 "
    "1.1.0-next.61 1.1.0-next.62 1.1.0-next.85 1.1.0-next.103 2.0.0-next.03604a46 "
    "2.0.0-next.096703ab 2.0.0-next.101 2.0.0-next.102 2.0.0-next.103 "
    "2.0.0-next.104 2.0.0-next.2150693d 2.0.0-next.247 2.0.0-next.260 "
    "2.0.0-next.279 2.0.0-next.281 2.0.0-next.299 2.0.0-next.300 "
    "2.0.0-next.3e165448 2.0.0-next.47d2d941 2.0.0-next.66cc7a90 2.0.0-next.74 "
    "2.0.0-next.75 2.0.0-next.81 2.0.0-next.91 2.0.0-next.9754a231 "
    "2.0.0-next.a671462c 2.0.0-next.b0cbf2ca 2.0.0-next.b2fd8db8 "
    "2.0.0-next.fb6e6f70"
).split()
OLD = "2020-01-01T00:00:00.000Z"


def packument(name, upstream, published, tags):
    versions = {
        v: {
            "name": name,
            "version": v,
            "dist": {
                "tarball": f"{upstream}/npm/{name}/-/{name}-{v}.tgz",
                "shasum": "0" * 40,
            },
        }
        for v in published
    }
    times = {"created": OLD, "modified": max(published.values())}
    times.update(published)
    return {"name": name, "dist-tags": tags, "time": times, "versions": versions}


def main():
    kind, name, upstream = sys.argv[1], sys.argv[2], sys.argv[3]
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if kind == "mixed":
        doc = packument(name, upstream, {v: OLD for v in MIXED}, {"latest": "1.0.11"})
    else:
        published = {"1.0.0": OLD, "1.1.0": OLD, "2.0.0-beta.1": OLD, "1.2.0": now}
        latest = "1.1.0" if kind == "keep" else "1.2.0"
        doc = packument(name, upstream, published, {"latest": latest, "next": "2.0.0-beta.1"})
    print(json.dumps(doc))


if __name__ == "__main__":
    main()
