#!/usr/bin/env python3
"""Tiny stdlib-only Azure Blob client for Azurite (Shared Key auth).

Used by profiles/storage.azurite.yml (create the container before the backend
starts) and by the azure-default-backend oracle (list blob names).

    azurite_blob.py mkcontainer
    azurite_blob.py list [PREFIX]      # one blob name per line

Environment: AZURITE_URL (path-style endpoint incl. the account, default
https://azurite:10000/dtfaccount), AZURITE_ACCOUNT, AZURITE_KEY,
AZURITE_CONTAINER, AZURITE_CAFILE (CA bundle for https; unset = no
verification, for the oracle's host-side listing of a throwaway emulator). Retries for up to 60 s so it can run as a startup sidecar.
"""
import base64
import email.utils
import hashlib
import hmac
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

URL = os.environ.get("AZURITE_URL", "https://azurite:10000/dtfaccount").rstrip("/")
ACCOUNT = os.environ.get("AZURITE_ACCOUNT", "dtfaccount")
# base64 of 32 'A' bytes, deliberately low-entropy: the test-only account that
# profiles/storage.azurite.yml registers through AZURITE_ACCOUNTS.
KEY = os.environ.get("AZURITE_KEY", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=")
CONTAINER = os.environ.get("AZURITE_CONTAINER", "ak-artifacts")
VERSION = "2021-08-06"
CAFILE = os.environ.get("AZURITE_CAFILE", "")
CTX = ssl.create_default_context(cafile=CAFILE) if CAFILE else ssl._create_unverified_context()


def request(method, path, query):
    """Signed request; path is relative to the account (e.g. '/ak-artifacts')."""
    date = email.utils.formatdate(usegmt=True)
    headers = {"x-ms-date": date, "x-ms-version": VERSION}
    canon_headers = "".join(f"{k}:{v}\n" for k, v in sorted(headers.items()))
    endpoint_path = urllib.parse.urlparse(URL).path  # '/dtfaccount'
    canon_res = f"/{ACCOUNT}{endpoint_path}{path}"
    for k in sorted(query):
        canon_res += f"\n{k.lower()}:{query[k]}"
    # urllib sends Content-Type: application/x-www-form-urlencoded with any
    # body, so a PUT names its type explicitly and signs it.
    ctype = "application/octet-stream" if method == "PUT" else ""
    sts = "\n".join([method, "", "", "", "", ctype, "", "", "", "", "", ""]) + "\n" + canon_headers + canon_res
    sig = base64.b64encode(hmac.new(base64.b64decode(KEY), sts.encode(), hashlib.sha256).digest()).decode()
    headers["Authorization"] = f"SharedKey {ACCOUNT}:{sig}"
    qs = urllib.parse.urlencode(query)
    req = urllib.request.Request(f"{URL}{path}{'?' + qs if qs else ''}", method=method, headers=headers)
    if method == "PUT":
        req.data = b""
        req.add_header("Content-Type", ctype)
    return urllib.request.urlopen(req, timeout=10, context=CTX)


def mkcontainer():
    deadline = time.time() + 60
    while True:
        try:
            request("PUT", f"/{CONTAINER}", {"restype": "container"})
            print("container-ready")
            return 0
        except urllib.error.HTTPError as e:
            if e.code == 409:
                print("container-ready (exists)")
                return 0
            err = f"HTTP {e.code}: {e.read()[:200]!r}"
        except OSError as e:
            err = str(e)
        if time.time() > deadline:
            print(f"mkcontainer FAILED: {err}", file=sys.stderr)
            return 1
        time.sleep(1)


def list_blobs(prefix):
    marker = ""
    while True:
        q = {"restype": "container", "comp": "list"}
        if prefix:
            q["prefix"] = prefix
        if marker:
            q["marker"] = marker
        root = ET.fromstring(request("GET", f"/{CONTAINER}", q).read())
        for name in root.iter("Name"):
            print(name.text)
        marker = (root.findtext("NextMarker") or "").strip()
        if not marker:
            return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "mkcontainer":
        sys.exit(mkcontainer())
    if cmd == "list":
        sys.exit(list_blobs(sys.argv[2] if len(sys.argv) > 2 else ""))
    print(__doc__, file=sys.stderr)
    sys.exit(2)
