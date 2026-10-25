"""Checks for the conda-jlap-incremental tier, run inside the client container.

  jlap_check.py cache <pkgs-cache-dir> <server-repodata-url> <filename>
      The client's cached noarch repodata (the cache JSON whose info.subdir is
      noarch) compared with a full fetch of repodata.json. Prints JSON:
      {"found", "equal", "listed", "server_listed", "records"}.
  jlap_check.py chain <jlap-url> <repodata-url>
      Fetches the whole JLAP and verifies the BLAKE2b chain the way conda's
      reader does, and whether its footer names the BLAKE2b-256 of the
      repodata.json served now. Prints {"ok", "patches", "latest_is_served"}.
"""
import glob
import hashlib
import json
import os
import sys
import urllib.request


def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def listed(doc, fn):
    return fn in doc.get("packages", {}) or fn in doc.get("packages.conda", {})


def cache(cache_dir, url, fn):
    server = json.loads(fetch(url))
    found = None
    for path in glob.glob(os.path.join(cache_dir, "*.json")):
        if path.endswith(".info.json") or path.endswith(".state.json"):
            continue
        try:
            with open(path, "rb") as f:
                doc = json.load(f)
        except Exception:
            continue
        if isinstance(doc, dict) and doc.get("info", {}).get("subdir") == "noarch":
            found = doc
    out = {"found": found is not None, "server_listed": listed(server, fn)}
    if found is not None:
        out.update({
            "equal": found == server,
            "listed": listed(found, fn),
            "records": len(found.get("packages", {})) + len(found.get("packages.conda", {})),
        })
    print(json.dumps(out))


def chain(url, repodata_url):
    try:
        served = hashlib.blake2b(fetch(repodata_url), digest_size=32).hexdigest()
        lines = fetch(url).split(b"\n")
        iv = bytes.fromhex(lines[0].decode())
        for line in lines[1:-1]:
            iv = hashlib.blake2b(line, key=iv, digest_size=32).digest()
        ok = iv.hex() == lines[-1].decode()
        footer = json.loads(lines[-2])
        print(json.dumps({"ok": ok, "patches": len(lines) - 3,
                          "latest_is_served": footer.get("latest") == served}))
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": str(e)}))


if __name__ == "__main__":
    if sys.argv[1] == "cache":
        cache(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        chain(sys.argv[2], sys.argv[3])
