# Contributing to NDT7 C Library

Thank you for your interest in contributing! This document outlines the project's scope and contribution guidelines.

## Project Scope

This library is designed as a **practical, lightweight C implementation** of NDT7-style network testing. It prioritizes:

- ✅ **Operational usefulness** over protocol purity
- ✅ **Repeatability** and deterministic behavior
- ✅ **Edge-friendly** deployment (Ubuntu Core, embedded Linux)
- ✅ **Minimal dependencies** (C, OpenSSL, WebSocket)

It does **not** aim for:

- ❌ Full protocol parity with ndt7-client-cc
- ❌ Regulatory-grade benchmarking compliance
- ❌ One-to-one Cloudflare Speed Test metric matching
- ❌ Complete NDT7 specification coverage

## Contribution Guidelines

### Before Contributing

1. **Check the scope**: Does your contribution align with the Design Goals (see README)?
2. **Review existing issues**: Check if your idea is already being discussed
3. **For protocol features**: Consider if it's essential for practical use or just protocol completeness

### What We Welcome

- **Bug fixes**: Especially for edge cases in WebSocket handling, TLS, or connection management
- **Performance improvements**: Better throughput, lower memory usage, faster JSON generation
- **Documentation**: Clearer examples, better API docs, usage guides
- **Platform support**: Fixes for different Linux distributions, embedded systems
- **Practical features**: Locate API integration, better error messages, configuration options

### What We're Cautious About

- **Protocol completeness features**: If it's not needed for practical use, we may defer it
- **Heavy dependencies**: We want to keep dependencies minimal
- **Breaking API changes**: We prefer backward-compatible additions

### Code Style

- Follow existing C style (C11 standard)
- Use meaningful variable names
- Add comments for non-obvious logic
- Keep functions focused and testable
- Prefer clarity over cleverness

### Testing

- Test your changes with real NDT7 servers
- Verify JSON output is valid
- Check memory usage (especially for embedded targets)
- Test on Ubuntu Core if possible

### Pull Request Process

1. **Fork and branch**: Create a feature branch from `main`
2. **Make changes**: Follow the guidelines above
3. **Update docs**: If adding features, update README/USAGE.md
4. **Test thoroughly**: Verify your changes work as expected
5. **Submit PR**: Include a clear description of what and why

### Questions?

If you're unsure whether a contribution fits the project scope, feel free to:
- Open an issue to discuss first
- Ask in the PR description
- Check the README's "Design Goals & Non-Goals" section

## Roadmap

Current priorities (v1.x):
- ✅ Basic download/upload testing
- ✅ JSON output
- ⚠️ Locate API integration (in progress)
- ⚠️ Better error handling
- ⚠️ More comprehensive testing

Future considerations (v2.x):
- Full protocol control message handling
- Optional TCP_INFO integration (if available)
- Additional metric collection methods

Thank you for helping make this library better!

