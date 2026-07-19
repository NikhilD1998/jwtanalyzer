# JWT Security Analysis

## Security Score

- **Score:** 55/100
- **Risk:** HIGH

## Findings

### Issuer
- Status: WARN
- Severity: MEDIUM
- Issue: iss claim missing.
- Recommendation: Specify the token issuer.

### Audience
- Status: WARN
- Severity: MEDIUM
- Issue: aud claim missing.
- Recommendation: Restrict the token to an intended audience.

### JWT ID
- Status: WARN
- Severity: LOW
- Issue: jti claim missing.
- Recommendation: Include a unique token identifier to help prevent replay attacks.

### Expiration
- Status: WARN
- Severity: MEDIUM
- Issue: exp claim missing.
- Recommendation: Include an expiration time.

### Not Before
- Status: WARN
- Severity: LOW
- Issue: nbf claim missing.
- Recommendation: Add nbf if delayed activation is required.

### Privileges
- Status: WARN
- Severity: MEDIUM
- Issue: Privileged token detected.
- Recommendation: Review administrative tokens carefully.

### Token Lifetime
- Status: WARN
- Severity: LOW
- Issue: Cannot calculate token lifetime.
- Recommendation: Include both exp and iat claims.

## Recommendations

- Specify the token issuer.
- Restrict the token to an intended audience.
- Include a unique token identifier to help prevent replay attacks.
- Include an expiration time.
- Add nbf if delayed activation is required.
- Review administrative tokens carefully.
- Include both exp and iat claims.