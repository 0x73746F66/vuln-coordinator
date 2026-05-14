---
title: "Go modules"
description: "go.mod, go.sum, replace directives, GOSUMDB integrity, vendor mode."
weight: 40
---

## Go modules (`go.mod` + `go.sum`)

```bash
go get foo.dev/bar@v1.2.3

# Coerce a transitive — go.mod:
#   require foo.dev/bar v1.2.3
#   replace foo.dev/bar => foo.dev/bar v1.2.3
go mod tidy
```

`replace` directives are the official mechanism for coerced transitives — they override what's recorded in dependent modules' `go.mod` files. `go.sum` carries `h1:` checksums verified at module-cache time; `GOSUMDB=sum.golang.org` validates against the checksum database. Vendor mode (`go mod vendor`) bakes the deps into `vendor/`; the build uses `-mod=vendor`.

Gotcha: `replace` is build-local — it doesn't propagate to consumers of your module, so library authors should publish a fixed release rather than rely on `replace`.

## Reachability

- `go mod why <module>` produces the import chain from your main module to a target.
- `go list -deps -json ./... | jq` walks every transitive.
- `go tool callgraph -algo=cha` from `golang.org/x/tools/cmd/callgraph` produces a static call graph.
- Runtime: `go test -coverprofile=cover.out ./... && go tool cover -html=cover.out`.
