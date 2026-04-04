.PHONY: build test clean fmt clippy start stop

LIMA_VM = ebpf-dev
PROJECT_DIR = $(HOME)/Dev/sfp

build:
	limactl start $(LIMA_VM) || true
	limactl shell $(LIMA_VM) -- bash -c "cd $(PROJECT_DIR) && CARGO_TARGET_DIR=/tmp/sfp-target cargo build"
	limactl stop $(LIMA_VM)

test:
	limactl start $(LIMA_VM) || true
	limactl shell $(LIMA_VM) -- bash -c "cd $(PROJECT_DIR) && CARGO_TARGET_DIR=/tmp/sfp-target cargo test"
	limactl stop $(LIMA_VM)

clean:
	limactl start $(LIMA_VM) || true
	limactl shell $(LIMA_VM) -- bash -c "rm -rf /tmp/sfp-target"
	limactl stop $(LIMA_VM)

format:
	cargo +nightly fmt --all

check:
	limactl start $(LIMA_VM) || true
	limactl shell $(LIMA_VM) -- bash -c "cd $(PROJECT_DIR) && CARGO_TARGET_DIR=/tmp/sfp-target cargo clippy"
	limactl stop $(LIMA_VM)

start:
	limactl start $(LIMA_VM)

stop:
	limactl stop $(LIMA_VM)
