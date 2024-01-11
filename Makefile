.PHONY: build
build:
	docker -c desktop-linux run --rm -it -v .:/app -w /app rust cargo build --release

.PHONY: run
run:
	docker -c desktop-linux run --rm -it -v .:/app -w /app rust /bin/bash -c '\
		for i in $$(seq 1 40); do echo "Run $$i..."; ./target/release/stoopid $$i 100; rm file_*; done'
