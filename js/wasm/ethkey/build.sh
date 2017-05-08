# Remove previous build to avoid name conflicts
rm -rf target/wasm32-unknown-emscripten/*

# Build using nightly rustc + emscripten
rustup run nightly cargo build --release --target=wasm32-unknown-emscripten

# Copy final WASM file over
cp ./target/wasm32-unknown-emscripten/release/deps/parity_ethkey_wasm-*.wasm ../../src/api/local/ethkey/ethkey.wasm
