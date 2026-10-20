#!/usr/bin/env python3
# =============================================================================
# make_vsix.py - build a minimal `vsce package`-shaped .vsix for the oracle
# =============================================================================
#   make_vsix.py <out> <publisher> <name> <version> [options]
#     --description TEXT   extension/package.json "description"
#     --engine RANGE       engines.vscode (default ^1.80.0); "" omits engines
#     --target PLATFORM    extension.vsixmanifest Identity/@TargetPlatform
#     --file PATH=TEXT     add an extra archive entry (repeatable), e.g. a
#                          bundled node_modules/<pkg>/package.json
#
# The archive carries the two manifests the backend reads (#3961):
# extension.vsixmanifest (Identity) and extension/package.json (publisher,
# name, version, displayName, description, engines.vscode), plus
# [Content_Types].xml and a tiny extension.js, as vsce writes them.
# Stdlib only.
# =============================================================================
import argparse
import json
import zipfile

ap = argparse.ArgumentParser()
ap.add_argument("out")
ap.add_argument("publisher")
ap.add_argument("name")
ap.add_argument("version")
ap.add_argument("--description", default="")
ap.add_argument("--engine", default="^1.80.0")
ap.add_argument("--target", default="")
ap.add_argument("--file", action="append", default=[])
a = ap.parse_args()

pkg = {
    "name": a.name,
    "publisher": a.publisher,
    "version": a.version,
    "displayName": f"{a.name} (DTF)",
    "description": a.description,
    "main": "./extension.js",
    "categories": ["Other"],
}
if a.engine:
    pkg["engines"] = {"vscode": a.engine}

target = f' TargetPlatform="{a.target}"' if a.target else ""
manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Language="en-US" Id="{a.name}" Version="{a.version}" Publisher="{a.publisher}"{target}/>
    <DisplayName>{a.name} (DTF)</DisplayName>
    <Description xml:space="preserve">{a.description}</Description>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="{a.engine}"/>
    </Properties>
  </Metadata>
  <Installation><InstallationTarget Id="Microsoft.VisualStudio.Code"/></Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/>
  </Assets>
</PackageManifest>
"""
content_types = """<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension=".json" ContentType="application/json"/><Default Extension=".js" ContentType="application/javascript"/><Default Extension=".vsixmanifest" ContentType="text/xml"/>
</Types>
"""
with zipfile.ZipFile(a.out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("[Content_Types].xml", content_types)
    z.writestr("extension.vsixmanifest", manifest)
    z.writestr("extension/package.json", json.dumps(pkg, indent=2))
    z.writestr("extension/extension.js", "exports.activate = () => {};\n")
    for spec in a.file:
        path, _, text = spec.partition("=")
        z.writestr(path, text)
