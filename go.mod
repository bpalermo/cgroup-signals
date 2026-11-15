module github.com/bpalermo/cgroup-signals

go 1.27.2

require (
	github.com/prometheus/client_golang v1.25.0
	github.com/prometheus/client_model v0.6.3
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/sys v0.49.0
)

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cilium/ebpf v0.22.0
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/uudashr/gocognit v1.2.2 // indirect
	golang.org/x/exp/typeparams v0.0.0-20260209203927-2842357ff358 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	honnef.co/go/tools v0.8.2 // indirect
)

tool (
	github.com/uudashr/gocognit/cmd/gocognit
	honnef.co/go/tools/cmd/staticcheck
)
