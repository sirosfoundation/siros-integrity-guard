.PHONY: build release test fmt clippy clean deb

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt --all

clippy:
	cargo clippy -- -D warnings

clean:
	cargo clean

deb: release
	dpkg-buildpackage -us -uc -b

musl:
	cargo build --release --target x86_64-unknown-linux-musl
