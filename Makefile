.PHONY: local local-dev test proto-gen

local:
	cargo build -p ostrich-bin --release

local-dev:
	cargo build -p ostrich-bin

test:
	cargo test -p ostrich -- --nocapture

proto-gen:
	./scripts/regenerate_proto_files.sh
