#!/bin/sh
# Builds the installable package (a zip with a manifest) without needing npm or vsce.
set -e
cd "$(dirname "$0")"
rm -rf .pack && mkdir -p .pack/extension
cp package.json extension.js README.md .pack/extension/
cp extension.vsixmanifest '[Content_Types].xml' .pack/
rm -f orb-line-counts-0.1.0.vsix
(cd .pack && zip -q -r -X ../orb-line-counts-0.1.0.vsix '[Content_Types].xml' extension.vsixmanifest extension)
rm -rf .pack
echo "orb-line-counts-0.1.0.vsix"
