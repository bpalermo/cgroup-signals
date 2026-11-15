#!/usr/bin/env bash
# Refuses a packaged chart that is not the one for this commit: the publish
# workflow runs it between `bazel build` and the push, so a chart whose version
# or pinned image is not this commit's is never pushed (a pushed version is
# never moved, so a wrong one cannot be repaired).
#
# Usage: verify-chart.sh <chart.tgz> <image-index-digest> <chart-version> <commit>
#   chart-version  what bazel/workspace_status.sh stamped (STABLE_CHART_VERSION)
#   commit         the full commit being published
# Checks, on the chart as packaged:
#   - Chart.yaml: name cgroup-signals, version == <chart-version>, and for a
#     snapshot ("-dev.") a version that ends in .g<first 12 of the commit>
#   - values.yaml: image.digest == <image-index-digest>, the index this commit's
#     build produced, and no stamp placeholder left ("{@" or "{STABLE_")
set -euo pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 <chart.tgz> <image-index-digest> <chart-version> <commit>" >&2
	exit 2
fi
chart="$1" want_digest="$2" want_version="$3" commit="$4"

fail() {
	echo "::error::verify-chart: $1" >&2
	exit 1
}

[[ "${want_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "expected digest '${want_digest}' is not sha256:<64 hex>"
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || fail "commit '${commit}' is not a full commit"

chart_yaml="$(tar -xzOf "${chart}" cgroup-signals/Chart.yaml)" || fail "no cgroup-signals/Chart.yaml in ${chart}"
values_yaml="$(tar -xzOf "${chart}" cgroup-signals/values.yaml)" || fail "no cgroup-signals/values.yaml in ${chart}"

field() { # file-content key: the unquoted value of a top-level or two-space-indented key
	sed -nE "s/^ {0,2}$2: *\"?([^\"]*)\"?$/\1/p" <<<"$1" | head -1
}

name="$(field "${chart_yaml}" name)"
version="$(field "${chart_yaml}" version)"
digest="$(field "${values_yaml}" digest)"

[[ "${name}" == cgroup-signals ]] || fail "chart name is '${name}'"
[[ "${version}" == "${want_version}" ]] || fail "chart version is '${version}', the build stamped '${want_version}'"
if [[ "${version}" == *-dev.* && "${version}" != *".g${commit:0:12}" ]]; then
	fail "chart version '${version}' does not end in .g${commit:0:12}: it is not this commit's"
fi
[[ "${digest}" == "${want_digest}" ]] || fail "chart pins image '${digest}', this commit's build produced '${want_digest}'"
if grep -qE '\{@|\{STABLE_' <<<"${chart_yaml}${values_yaml}"; then
	fail "an unreplaced stamp placeholder is left in the chart"
fi

echo "chart ${name} ${version} pins ${digest}"
