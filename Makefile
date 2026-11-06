.DEFAULT_GOAL := all

NPM ?= npm
CARGO ?= cargo
APP := target/release/happyworking-vpn-app
HELPER := target/release/happyworking-vpn-helper

.PHONY: all build release run test clean

all: build

build: node_modules
	$(NPM) run build
	@printf '\n构建完成：\n  %s\n  %s\n' '$(APP)' '$(HELPER)'

release: build

run: build
	$(APP)

test: node_modules
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	$(CARGO) test --workspace
	$(NPM) test
	$(NPM) run check

node_modules: package.json package-lock.json
	$(NPM) ci

clean:
	$(CARGO) clean
	rm -rf dist
