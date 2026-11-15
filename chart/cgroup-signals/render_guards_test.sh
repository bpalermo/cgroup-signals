#!/usr/bin/env bash
# The chart's `fail` guards: a render that must be refused is refused, and the
# neighbouring one that must work works. Arguments: helm, the packaged chart.
set -euo pipefail

# --- begin runfiles.bash initialization v3 ---
set +e
f=bazel_tools/tools/bash/runfiles/runfiles.bash
# shellcheck disable=SC1090
source "${RUNFILES_DIR:-/dev/null}/${f}" 2>/dev/null ||
	source "$(grep -sm1 "^${f} " "${RUNFILES_MANIFEST_FILE:-/dev/null}" | cut -f2- -d' ')" 2>/dev/null ||
	source "$0.runfiles/${f}" 2>/dev/null ||
	source "$(grep -sm1 "^${f} " "$0.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null ||
	source "$(grep -sm1 "^${f} " "$0.exe.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null ||
	{
		echo >&2 "ERROR: cannot find ${f}"
		exit 1
	}
set -e
# --- end runfiles.bash initialization v3 ---

helm="$(rlocation "$1")"
chart="$(rlocation "$2")"

render() { "${helm}" template guard "${chart}" --namespace ns "$@" 2>&1; }

fails() { # message-substring, helm args...
	local want="$1" out
	shift
	if out="$(render "$@")"; then
		echo "FAIL: render of '$*' succeeded, want an error containing '${want}'" >&2
		exit 1
	fi
	if ! grep -q -- "${want}" <<<"${out}"; then
		echo "FAIL: render of '$*' failed without '${want}':" >&2
		echo "${out}" >&2
		exit 1
	fi
}

works() {
	local out
	if ! out="$(render "$@")"; then
		echo "FAIL: render of '$*' failed:" >&2
		echo "${out}" >&2
		exit 1
	fi
}

works
works --set psi.windowUs=4000000
works --set psi.windowUs=1000000 --set privileged=true
fails "not a multiple of 2000000" --set psi.windowUs=1000000
fails "not a multiple of 2000000" --set psi.windowUs=3000000
fails "image.digest or image.tag is required" --set image.digest=
echo PASS
