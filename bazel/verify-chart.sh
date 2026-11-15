#!/usr/bin/env bash
# Refuses a packaged chart that is not the one for this commit: the publish
# workflow runs it between `bazel build` and the push, so a chart whose version
# or pinned image is not this commit's is never pushed (a pushed version is
# never moved, so a wrong one cannot be repaired).
#
# Usage: verify-chart.sh <chart-name> <chart.tgz> <image-index-digest> <chart-version> <commit>
#   chart-name     cgroup-signals or bpftrace-debug: the chart's name, and the directory
#                  inside the .tgz
#   chart-version  what bazel/workspace_status.sh stamped (STABLE_CHART_VERSION)
#   commit         the full commit being published
# Checks, on the chart as packaged:
#   - Chart.yaml: name == <chart-name>, version == <chart-version>, and for a
#     snapshot ("-dev.") a version that ends in .g<first 12 of the commit>
#   - values.yaml: image.digest == <image-index-digest>, the index this commit's
#     build produced, and no stamp placeholder left ("{@" or "{STABLE_")
set -euo pipefail

if [[ $# -ne 5 ]]; then
	echo "usage: $0 <chart-name> <chart.tgz> <image-index-digest> <chart-version> <commit>" >&2
	exit 2
fi
want_name="$1" chart="$2" want_digest="$3" want_version="$4" commit="$5"
[[ "${want_name}" =~ ^[a-z][a-z0-9-]*$ ]] || {
	echo "::error::verify-chart: chart name '${want_name}' is not a chart name" >&2
	exit 2
}

fail() {
	echo "::error::verify-chart: $1" >&2
	exit 1
}

[[ "${want_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "expected digest '${want_digest}' is not sha256:<64 hex>"
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || fail "commit '${commit}' is not a full commit"

chart_yaml="$(tar -xzOf "${chart}" "${want_name}/Chart.yaml")" || fail "no ${want_name}/Chart.yaml in ${chart}"
values_yaml="$(tar -xzOf "${chart}" "${want_name}/values.yaml")" || fail "no ${want_name}/values.yaml in ${chart}"

field() { # file-content key: the unquoted value of a top-level or two-space-indented key
	sed -nE "s/^ {0,2}$2: *\"?([^\"]*)\"?$/\1/p" <<<"$1" | head -1
}

name="$(field "${chart_yaml}" name)"
version="$(field "${chart_yaml}" version)"
digest="$(field "${values_yaml}" digest)"

[[ "${name}" == "${want_name}" ]] || fail "chart name is '${name}'"
[[ "${version}" == "${want_version}" ]] || fail "chart version is '${version}', the build stamped '${want_version}'"
if [[ "${version}" == *-dev.* && "${version}" != *".g${commit:0:12}" ]]; then
	fail "chart version '${version}' does not end in .g${commit:0:12}: it is not this commit's"
fi
[[ "${digest}" == "${want_digest}" ]] || fail "chart pins image '${digest}', this commit's build produced '${want_digest}'"
if grep -qE '\{@|\{STABLE_' <<<"${chart_yaml}${values_yaml}"; then
	fail "an unreplaced stamp placeholder is left in the chart"
fi

echo "chart ${name} ${version} pins ${digest}"
