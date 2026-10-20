#!/bin/sh
# POSIX sh, including BusyBox ash. The only argument is a local JSON filename.
set -eu
[ "$#" -eq 1 ] || exit 2
case "$1" in /*) ;; *) exit 2;; esac
[ -f "$1" ] && [ -r "$1" ] || exit 1
# Replace this body with your service integration. Read JSON with a real JSON
# parser if extracting fields; do not source the file or evaluate its contents.
# Example integration: /usr/local/bin/my-service-reconfigure --json "$1"
cat "$1"
