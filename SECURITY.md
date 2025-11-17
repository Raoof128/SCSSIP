# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by emailing the security team or opening a private security advisory on GitHub.

### What to Include

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Status Update**: Every 7 days until resolved
- **Fix Timeline**: Critical issues within 7 days, High within 14 days, Medium/Low within 30 days

## Security Best Practices

### For Users

1. **API Keys**: Never commit API keys or secrets to version control
   - Use environment variables or secret management tools
   - Rotate API keys regularly (NVD, GitHub tokens)

2. **Database**:
   - Use strong passwords for PostgreSQL
   - Enable SSL/TLS for database connections in production
   - Implement database backup and encryption at rest

3. **Network**:
   - Deploy behind a reverse proxy (nginx, Traefik)
   - Enable HTTPS with valid TLS certificates
   - Implement rate limiting at the reverse proxy level

4. **Authentication**:
   - Implement OAuth2/OIDC for production deployments
   - Use API keys for service-to-service communication
   - Rotate credentials regularly

5. **Updates**:
   - Keep dependencies up to date
   - Subscribe to security advisories for Python, FastAPI, and PostgreSQL
   - Monitor CVE feeds for components you use

### For Developers

1. **Code Security**:
   - All code changes require security review
   - Use static analysis tools (Bandit, Semgrep)
   - Follow OWASP Top 10 guidelines

2. **Dependencies**:
   - Run `poetry update` regularly
   - Review Dependabot alerts promptly
   - Verify dependency signatures when possible

3. **Testing**:
   - Write security-focused tests
   - Test for injection vulnerabilities
   - Validate all user inputs

4. **Secrets Management**:
   - Never hardcode secrets
   - Use `.env` files locally (never committed)
   - Use secret managers in production (AWS Secrets Manager, HashiCorp Vault)

## Known Security Considerations

### Input Validation

- **SBOM Files**: Maximum file size enforced (10MB default)
- **File Type Validation**: JSON schema validation for CycloneDX and SPDX
- **SQL Injection**: Parameterized queries via SQLAlchemy ORM
- **Path Traversal**: Validated file paths, no directory traversal allowed

### Rate Limiting

- API endpoints should be rate-limited in production
- External API calls (NVD, OSV, GitHub) respect rate limits
- Implement backoff strategies for retries

### Data Privacy

- **PII**: SBOMs may contain author/developer information
- **Sensitive Data**: Component names could reveal internal architecture
- **Retention**: Implement data retention policies per your requirements

### Authentication & Authorization

- Current version: **No authentication** (designed for internal use)
- **Production Deployment**: Implement OAuth2 or API key authentication
- **RBAC**: Consider role-based access control for multi-tenant deployments

## Security Features

### Implemented

- ✅ Input validation and sanitization
- ✅ Parameterized database queries (SQL injection protection)
- ✅ CORS configuration
- ✅ File upload size limits
- ✅ Dependency vulnerability scanning (via Dependabot)
- ✅ Container scanning (via Trivy in CI)

### Recommended for Production

- 🔒 OAuth2/OIDC authentication
- 🔒 API key management
- 🔒 Rate limiting per endpoint
- 🔒 TLS/SSL encryption
- 🔒 Database encryption at rest
- 🔒 Audit logging
- 🔒 WAF (Web Application Firewall)

## Compliance

This platform helps you achieve compliance with:

- **SLSA Framework**: Levels 1-3 validation
- **NTIA Minimum Elements**: SBOM completeness validation
- **OWASP**: Follows OWASP secure coding guidelines
- **CIS Benchmarks**: Docker containers follow CIS Docker Benchmark

## Security Audits

### Latest Audit

- **Date**: 2025-11-16
- **Type**: Internal Code Review
- **Status**: No critical issues found
- **Action Items**: See AUDIT_REPORT.md

### Recommended Audits

- **Penetration Testing**: Annually for production deployments
- **Code Review**: Every major release
- **Dependency Audit**: Monthly
- **Container Scanning**: Every build

## Contact

For security concerns, please contact:
- **Security Team**: [Your contact method]
- **GitHub Security**: Use GitHub Security Advisories
- **PGP Key**: [If applicable]

## Acknowledgments

We appreciate the security research community and will acknowledge researchers who responsibly disclose vulnerabilities:

- [List of security researchers who have helped]

---

**Last Updated**: 2025-11-16
**Version**: 1.0
