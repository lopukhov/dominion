default:
  just --list

# Check for incompatible licenses and security advisories, lint and run tests
check:
  # cargo deny check
  cargo clippy
  cargo test

# Build binary with selected PROFILE
build PROFILE:
  cargo build --profile {{PROFILE}}

# Build binary in optimized mode, with CPU native optimizations. Might make the binary incompatible for older CPUs
native:
  RUSTFLAGS="-C target-cpu=native" cargo build --profile optimized
