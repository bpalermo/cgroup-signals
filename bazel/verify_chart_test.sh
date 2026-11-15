#!/usr/bin/env bash
# verify-chart.sh accepts the chart of a commit and refuses every way it can be
# another's. Fixtures are packaged by hand: a tarball with the two files.
set -euo pipefail

script="$1"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

commit=b60ce93e9360aabbccddeeff00112233445566ff
digest=sha256:e2490b75d9c42a2d2c2b3dcf9b8799d663f30e1f886f1fcc3120a7fbc8ceebe2
version=0.1.0-dev.20261115173333.gb60ce93e9360

# pack <file> <name> <version> <digest>
pack() {
	local dir
	dir="$(mktemp -d -p "${work}")"
	mkdir "${dir}/cgroup-signals"
	printf 'apiVersion: v2\nname: %s\nversion: %s\nappVersion: x\n' "$2" "$3" >"${dir}/cgroup-signals/Chart.yaml"
	printf 'image:\n  repository: ghcr.io/bpalermo/cgroup-signals\n  digest: "%s"\n  tag: ""\n' "$4" >"${dir}/cgroup-signals/values.yaml"
	tar -czf "$1" -C "${dir}" cgroup-signals
}

pack "${work}/good.tgz" cgroup-signals "${version}" "${digest}"
pack "${work}/otherdigest.tgz" cgroup-signals "${version}" "sha256:$(printf 'a%.0s' {1..64})"
pack "${work}/othercommit.tgz" cgroup-signals 0.1.0-dev.20261115173333.g000000000000 "${digest}"
pack "${work}/release.tgz" cgroup-signals 0.1.0 "${digest}"
pack "${work}/unstamped.tgz" cgroup-signals "{STABLE_CHART_VERSION}" "${digest}"
pack "${work}/placeholder.tgz" cgroup-signals "${version}" "{@//cgroup-signals:image_push.digest}"
pack "${work}/othername.tgz" connector "${version}" "${digest}"

ok() { # name chart version
	"${script}" "${work}/$2" "${digest}" "$3" "${commit}" >/dev/null 2>"${work}/err" ||
		{
			echo "FAIL: $1 was refused:" >&2
			cat "${work}/err" >&2
			exit 1
		}
}
refused() { # name chart version
	if "${script}" "${work}/$2" "${digest}" "$3" "${commit}" >/dev/null 2>&1; then
		echo "FAIL: $1 was accepted" >&2
		exit 1
	fi
}

ok "this commit's chart" good.tgz "${version}"
ok "a release chart" release.tgz 0.1.0
refused "a chart pinning another digest" otherdigest.tgz "${version}"
refused "a chart of another commit" othercommit.tgz 0.1.0-dev.20261115173333.g000000000000
refused "a version the build did not stamp" good.tgz 0.1.0-dev.1.gb60ce93e9360
refused "an unstamped version" unstamped.tgz "{STABLE_CHART_VERSION}"
refused "an unreplaced digest" placeholder.tgz "${version}"
refused "another chart" othername.tgz "${version}"
echo PASS
