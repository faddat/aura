# Aura Coding Guidelines

This repository is a Rust workspace. Contributions should follow these rules:

## Programmatic Checks
1. Format code with `cargo fmt --all` before committing. Verify with `cargo fmt --all -- --check`.
2. Run `cargo test --workspace` and ensure it succeeds. If tests fail due to missing dependencies or network access, mention this in the PR testing section.
3. Make sure that the code builds with `cargo build`
4. Make sure that we can get through clippy and apply automated fixes with `cargo clippy --fix --offline`

## Commit Messages
- Use short imperative subject lines (max 72 characters).
- Provide a concise body if necessary, wrapping at 72 characters.

## Pull Request Message
Include **Summary** and **Testing** sections describing code changes and the result of the programmatic checks.
