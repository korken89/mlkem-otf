# Host tests, QEMU measurements, the constant-time guard and lints
.PHONY: test test-host test-qemu ct-guard size lint bless

# A failing command before a pipe fails the recipe
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

QEMU_INCLUDE = $(shell dirname $$(dirname $$(readlink -f $$(command -v qemu-system-arm))))/include
PLUGIN := qemu/target/libicount.so

test: test-host test-qemu ct-guard

test-host:
	cargo test --release

# Fails if the stack or instruction counts differ from qemu/stack-usage.txt, or if
# encapsulation or decapsulation takes a different number of instructions for some input or
# leaves a secret on the stack. The checks run at opt-level 2, 3 and z too.
test-qemu: $(PLUGIN)
	cd qemu && cargo run --release | tee target/stack-usage.txt
	diff -u qemu/stack-usage.txt qemu/target/stack-usage.txt
	for opt in 2 3 z; do \
		(cd qemu && CARGO_PROFILE_RELEASE_OPT_LEVEL=$$opt cargo run --release --quiet \
			--target-dir target/opt-$$opt > target/opt-$$opt.txt) \
			|| { cat qemu/target/opt-$$opt.txt; exit 1; }; \
		echo "opt-level $$opt: $$(tail -n 1 qemu/target/opt-$$opt.txt)"; \
	done

# Fails on a division, a branch on secret data or a reachable panic in the machine code for
# Cortex-M0, M3, M4 and M33, or if the branches differ from guard/branch-counts.txt
ct-guard:
	scripts/ct-guard.sh

# Prints the code size of each operation
size:
	qemu/text-size.sh

lint:
	cargo fmt --check
	cargo clippy --all-targets --all-features -- -D warnings
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
	cd qemu && cargo fmt --check
	cd qemu && cargo clippy --release --bins -- -D warnings
	cd qemu && cargo clippy --release --bins --all-features -- -D warnings
	cd guard && cargo fmt --check
	cd guard && cargo clippy --release -- -D warnings
	cd guard && cargo clippy --release --features allow-panic -- -D warnings

# Overwrites qemu/stack-usage.txt and guard/branch-counts.txt with the current measurements
bless: $(PLUGIN)
	cd qemu && cargo run --release | tee stack-usage.txt
	BLESS=1 scripts/ct-guard.sh

$(PLUGIN): qemu/icount.c
	mkdir -p qemu/target
	$(CC) -shared -fPIC -O2 -Wall -Werror $$(pkg-config --cflags glib-2.0) -I$(QEMU_INCLUDE) -o $@ $<
