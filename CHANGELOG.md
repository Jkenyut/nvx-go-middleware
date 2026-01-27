# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-27

### Added
- Initial release of NVX Go Middleware
- Custom middleware for panic recovery with audit logging
- Request/response logger with customizable storage
- RSA signature validation for requests
- JWT authentication middleware
- Header validation (common, auth, public)
- Device validation (User-Agent, Device-ID, Platform, MAC)
- Integration with Chi middleware utilities
- Rate limiting support (via Chi Throttle)
- Gzip compression support (via Chi Compress)
- Request timeout handling
- Body size limiting
- CORS support
- Real IP extraction from proxied requests
- Security headers injection
- Context injection utilities
- Flexible middleware chaining (GlobalChain, PublicChain, AuthChain, AdminChain)
- Console and custom log storage support
- Comprehensive examples (basic and advanced)
- Full documentation in README.md

### Features
- Pure `net/http` compatibility
- No router dependency (works with any router or ServeMux)
- Configurable middleware chains
- Production-ready defaults
- Structured logging with zerolog
- Extensible LogStore interface

## [Unreleased]

### Planned
- Database log storage implementations (PostgreSQL, MySQL, MongoDB)
- Metrics and monitoring integration
- OpenTelemetry tracing support
- Additional authentication methods (OAuth2, API keys)
- Request/response encryption
- IP-based rate limiting
- Advanced CORS configuration
- Webhook signature validation
