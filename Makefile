.PHONY: docs build build-mimalloc build-jemalloc build-perf release release-mimalloc release-jemalloc release-perf


test-geoip:
	cargo test -p clash-lib --lib app::dns::resolver::tests

docs:
	@rm -rf ./docs
	@cargo doc -p clash_doc --no-deps
	@echo "<meta http-equiv=\"refresh\" content=\"0; url=clash_doc\">" > target/doc/index.html
	@cp -r target/doc ./docs

test-no-docker:
	CLASH_RS_CI=true cargo test --all --all-features


test-geoip-routing:
	cd test_routing && cargo run

test-geoip-run: build
	./target/debug/clash-rs -c ./clash-bin/tests/data/config/geoip-fallback-test.yaml

test-run: build
	./target/debug/clash-rs -c ./clash-bin/tests/data/config/geoip-fallback.yaml

# Default build (mimalloc)
build:
	cargo build

# Debug builds
build-mimalloc:
	cargo build --features mimalloc

build-jemalloc:
	cargo build --features jemallocator

build-perf:
	cargo build --features perf

# Release builds
release: release-mimalloc

release-mimalloc:
	cargo build --release --features mimalloc

release-jemalloc:
	cargo build --release --features jemallocator

release-perf:
	cargo build --release --features perf
