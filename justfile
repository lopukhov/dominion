default:
  just --list

# Check for incompatible licenses and security advisories, lint and run tests
check:
  # cargo deny check
  cargo clippy
  cargo test

# Profile the appropiate benchmark
profile SUITE BENCH:
  cargo bench --bench {{SUITE}} -- --profile-time 60 {{BENCH}}

# Build binary with selected PROFILE
build PROFILE:
  cargo build --profile {{PROFILE}}

# Build binary in optimized mode, with CPU native optimizations. Might make the binary incompatible for older CPUs
native:
  RUSTFLAGS="-C target-cpu=native" cargo build --profile optimized
