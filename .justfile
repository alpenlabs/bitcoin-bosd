alias b := build
alias c := check
alias f := fmt
alias t := test

_default:
   @just --list

# Build the project
build:
   cargo build

# Check code: formatting, compilation, linting, and commit signature
check:
   cargo fmt --all -- --check
   cargo check --all-features --all-targets --bins --lib --workspace --tests --benches
   cargo clippy --all-features --all-targets --bins --lib --workspace --tests --benches

# Format all code
fmt:
   cargo fmt --all

# Run all tests on the workspace with all features
test:
   cargo test --all-features --bins --lib --workspace
