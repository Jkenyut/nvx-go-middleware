# Contributing to NVX Go Middleware

Thank you for your interest in contributing! 🎉

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- Clear title and description
- Steps to reproduce
- Expected vs actual behavior
- Go version and OS
- Code sample if possible

### Suggesting Features

Feature suggestions are welcome! Please open an issue with:
- Clear description of the feature
- Use case / problem it solves
- Example implementation (if you have one)

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow existing code style
   - Add tests if applicable
   - Update documentation

4. **Test your changes**
   ```bash
   go test ./...
   go vet ./...
   ```

5. **Commit with clear messages**
   ```bash
   git commit -m "feat: add new feature X"
   git commit -m "fix: resolve issue with Y"
   git commit -m "docs: update README for Z"
   ```

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style

- Follow standard Go conventions
- Use `gofmt` to format code
- Keep functions focused and small
- Add comments for exported functions
- Use meaningful variable names

## Commit Message Convention

We follow conventional commits:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Adding tests
- `chore:` - Maintenance tasks

## Testing

- Add tests for new features
- Ensure all tests pass
- Maintain or improve code coverage

```bash
go test -v ./...
go test -cover ./...
```

## Documentation

- Update README.md if needed
- Add examples for new features
- Update CHANGELOG.md
- Add godoc comments

## Questions?

Feel free to open an issue for any questions!

Thank you for contributing! 🙏
