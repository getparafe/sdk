# Contributing to @getparafe/sdk

Thank you for your interest in contributing to the Parafe SDK.

## Development Setup

```bash
git clone https://github.com/getparafe/sdk.git
cd sdk
npm install
npm run build
npm test
```

## Running Tests

Unit tests run without any external dependencies:

```bash
npm run test:unit
```

Integration tests require a running Parafe broker:

```bash
PARAFE_TEST_BROKER_URL=http://localhost:3000 PARAFE_TEST_API_KEY=your-key npm run test:integration
```

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Make your changes
4. Run `npm run build && npm test` to verify
5. Commit and push
6. Open a PR against `main`

All PRs must pass CI (build + tests) before merging.

## Code Style

- TypeScript strict mode
- No external dependencies beyond `jose` (Ed25519 crypto)
- All public methods must have JSDoc comments
- New features need both unit and integration tests

## Reporting Issues

Use [GitHub Issues](https://github.com/getparafe/sdk/issues) for bugs and feature requests.

For security vulnerabilities, see [SECURITY.md](./SECURITY.md).
