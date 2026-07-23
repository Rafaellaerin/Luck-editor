.PHONY: all extension test native rust clean package

all: extension native rust

extension:
	npm run verify

native:
	cmake -S native -B native/build -DCMAKE_BUILD_TYPE=Release
	cmake --build native/build --parallel
	ctest --test-dir native/build --output-on-failure

rust:
	cargo test --workspace --manifest-path rust/Cargo.toml
	cargo clippy --workspace --all-targets --manifest-path rust/Cargo.toml

package:
	npm run package

clean:
	npm run clean
	rm -rf native/build rust/target
