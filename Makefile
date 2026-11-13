# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

PASSMCP_BIN ?= /Users/seb/Code/Public/Go/passmcp/build/passmcp

.PHONY: check test test-race lint reuse family lockstep example conformance

check: test test-race lint reuse family lockstep example conformance

test:
	go test -count=1 ./... -cover

test-race:
	go test -race -shuffle=on -count=1 ./... -cover

lint:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:" && gofmt -l . && exit 1)
	golangci-lint run ./...

reuse:
	reuse lint

family:
	./scripts/family.sh

lockstep:
	./scripts/lockstep.sh

example:
	go run ./examples/quickstart

conformance:
	@if [ -x "$(PASSMCP_BIN)" ]; then \
		mkdir -p build; \
		if [ -n "$$(git status --porcelain 2>/dev/null)" ]; then \
			go build -buildvcs=false -o build/stdio-server ./examples/stdio-server; \
		else \
			go build -o build/stdio-server ./examples/stdio-server; \
		fi; \
		"$(PASSMCP_BIN)" check --stdio --rps 0 --samples 2 --concurrency 2 --no-color --output json -- "$(CURDIR)/build/stdio-server" > build/passmcp-report.json; \
		python3 -c 'import json,sys; r=json.load(open("build/passmcp-report.json")); c=r["counts"]; s=r["score"]; print("conformance: score=%s grade=%s pass=%d warn=%d fail=%d" % (s["total"], s["grade"], c["pass"], c["warn"], c["fail"])); sys.exit(0 if c["fail"]==0 and c["warn"]==0 else 1)'; \
	else \
		echo "conformance: skipped ($(PASSMCP_BIN) not found)"; \
	fi
