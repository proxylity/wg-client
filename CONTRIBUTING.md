# Contributing to Proxylity.WireGuardClient

Thank you for your interest in contributing! This document outlines how to get the project building and running locally, and what to expect from the contribution process.

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| .NET SDK | 8.0 + 10.0 | The library targets net8.0; the test project targets net10.0 |
| AWS CLI | any recent | Required only for integration tests |
| SAM CLI | any recent | Required only for integration tests |

## Building

```sh
dotnet build
```

## Running tests

### Unit and protocol tests (no external dependencies)

```sh
dotnet test --filter "Category!=Integration"
```

All tests in `ProtocolHandshakeTests`, `ProtocolTransportTests`, and `WireGuardClientUnitTests` are purely in-memory. No network access or AWS credentials are required.

### Integration tests

See [README.md §Testing](README.md#testing) for full setup instructions. The integration test is **skipped** automatically when the required environment variables are absent, so it will never block a local build.

## Making a change

1. Fork the repository and create a feature branch from `main`.
2. Keep changes focused — one logical change per pull request.
3. Ensure `dotnet test --filter "Category!=Integration"` passes with no failures.
4. Add or update tests if you're changing behavior.
5. Open a PR against `main` with a clear description of what you changed and why.

## Public API changes

This library is pre-1.0 (`0.x`), so breaking changes are possible but should be minimized. If you need to change a public API, note it clearly in the PR description.

## Code style

The project uses the .NET default style. There is no `.editorconfig` at present; follow the surrounding code style when in doubt.

## Reporting bugs

Please open a GitHub issue with a minimal reproduction and the .NET version you are running on.
