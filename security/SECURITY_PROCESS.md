# GlobePulse Security Process & Guidelines

This document defines the security governance, review workflows, severity classification, and domain-specific security checklists for all engineers working on the **GlobePulse** platform.

---

## 1. Security Review Workflow

All code contributions to GlobePulse must undergo automated and manual security verification prior to merging into production branches.

```
       +-------------------------+
       |   Developer Local Dev   |
       +-------------------------+
                    |
                    v
       +-------------------------+
       |  Pre-Commit Hook Run    |  <-- security/pre_commit.sh
       | (security_check.py)     |
       +-------------------------+
                    |
          Pass / Fail Check
                    |
         +----------+----------+
         |                     |
      [ Passed ]          [ Failed ]
         |                     |
         v                     v
+------------------+  +------------------+
|  Git Commit &    |  |  Fix Violations  |
|  Push to PR      |  |  Local Re-check  |
+------------------+  +------------------+
         |
         v
+----------------------------------------+
|  CI Pipeline Security Verification     |
|  - Automated Secret Scan               |
|  - Static Code Analysis (AST)          |
|  - Dependency Vulnerability Audit      |
|  - AI Guardrails Verification          |
+----------------------------------------+
         |
         v
+----------------------------------------+
|  Peer & Security Lead PR Sign-off      |
+----------------------------------------+
         |
         v
+----------------------------------------+
|  Deployment to Production / Staging    |
+----------------------------------------+
```

---

## 2. Severity Levels & SLA Matrix

Vulnerabilities discovered during automated scanning or security audits are classified into four severity levels.

| Severity Level | Definition & Criteria | Target Resolution SLA | Escalation Action |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | Direct code execution, hardcoded production API/Service keys, unauthenticated admin bypass, remote shell execution, unvalidated LLM output executing commands, open read/write database rules. | **Immediate / Block Build** (< 24 Hours) | Immediately block PR/Release; alert Security Lead & DevOps. |
| **HIGH** | SQL/NoSQL Injection risks, SSRF with potential internal network probing, broken object-level authorization, direct prompt injection without boundaries, insecure deserialization, raw credential logging. | **Fix within 48 Hours** | Block PR merge; require security re-audit. |
| **MEDIUM** | Missing anti-CSRF or CORS misconfigurations, unpinned high-risk dependencies, weak cryptographic primitives (MD5/SHA1 usage), lack of rate limiting on sensitive APIs, verbose debug logs in production. | **Fix within 7 Days** (Current Sprint) | Flag in PR review; track via Jira/GitHub Issue. |
| **LOW** | Missing security headers (HSTS, CSP, X-Frame-Options), minor code hygiene issues, outdated non-vulnerable libraries, missing docstrings on security handlers. | **Fix within 30 Days** (Backlog) | Non-blocking warning in CI; address during maintenance. |

---

## 3. Secure Coding Guidelines

### Python (Backend Services & Pipelines)
- **Input Validation**: Use Pydantic or strict schema validation for all API request bodies, path parameters, and query parameters.
- **Safe Serialization**: Never use `pickle.loads()` or `yaml.unsafe_load()` on untrusted payloads. Use `json` or `yaml.safe_load()`.
- **Command Execution**: Avoid `subprocess.Popen(..., shell=True)` and `os.system()`. Use list-formatted argument arrays: `subprocess.run(["command", arg1, arg2], check=True)`.
- **Cryptography**: Standardize on `hashlib.sha256`, `hashlib.sha512`, or `secrets` for token generation. Never use `md5` or `sha1` for security-sensitive hashing.
- **Error Handling**: Catch specific exceptions. Never return raw stack traces or internal environment variables in API responses.

### JavaScript / TypeScript (Frontend Web UI)
- **DOM XSS Prevention**: Use React/Vite binding constructs (`{variable}`) instead of raw innerHTML. Avoid `dangerouslySetInnerHTML` unless explicitly sanitized with DOMPurify.
- **Dynamic Execution**: Prohibit usage of `eval()`, `new Function()`, and `document.write()`.
- **Navigation Safety**: Validate external links before assignment to `window.location.href`.

---

## 4. Authentication Checklist

- [ ] All public API endpoints require valid authentication tokens (Firebase ID Token / OAuth JWT) unless explicitly listed on an unauthenticated allowlist.
- [ ] JWT tokens must be cryptographically verified (algorithm, issuer, audience, expiration time `exp`).
- [ ] Revoked or expired credentials must fail closed immediately.
- [ ] Passwords/tokens must never be stored in plain text or logged to standard output/files.
- [ ] Session tokens must use secure flag, `HttpOnly`, and `SameSite=Strict` attribute policies when transported via cookies.
- [ ] Multi-tenant requests must enforce tenant ID matching against verified user token claims.

---

## 5. Authorization Checklist

- [ ] Every API endpoint and database operation implements Role-Based (RBAC) or Attribute-Based (ABAC) access control checks.
- [ ] **Object-Level Authorization (IDOR)**: Verify that the authenticated user owns or has permission to access the target resource ID (e.g. user, article, feed, subscription).
- [ ] Admin functions must check administrative privilege claims server-side, independent of UI component visibility.
- [ ] Deny access by default: Unhandled authorization branches must fail securely.

---

## 6. AI/LLM Security Checklist

- [ ] **Prompt/System Separation**: Treat all user inputs as untrusted data. Use strict system/user message boundaries.
- [ ] **Input Sanitization**: Strip or escape control tokens, prompt injection payloads, and instruction override formatting prior to forwarding to Gemini API.
- [ ] **Delimiter Isolation**: Surround user inputs with clear delimiter tags (e.g., `<user_input>...</user_input>`) in model prompts.
- [ ] **Tool Call Gating**: All function/tool calls suggested by the model must be validated against a whitelist and authorized before backend execution.
- [ ] **Output Escaping**: Model output rendered in HTML must be XSS-escaped; model output executed in shell or database must be parsed safely.
- [ ] **PII & Secret Filtering**: Scrub sensitive user data, internal IP addresses, and API credentials from prompt payloads sent to third-party LLMs.

---

## 7. SSRF (Server-Side Request Forgery) Checklist

- [ ] Any feature requesting external URLs must validate the destination host against an IP/domain whitelist.
- [ ] **Private IP Blocking**: Reject requests resolving to private, loopback, or cloud metadata IP addresses:
  - `127.0.0.0/8` (Loopback)
  - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (Private RFC 1918)
  - `169.254.169.254` (Cloud Instance Metadata Service)
  - `::1/128`, `fc00::/7`, `fe80::/10` (IPv6 Private/Link-local)
- [ ] Disable automatic HTTP redirect following or enforce strict redirect destination validation.
- [ ] Enforce request timeouts (e.g., max 5 seconds) to prevent Denial of Service via slow external endpoints.

---

## 8. WebSocket Security Checklist

- [ ] Validate the `Origin` header during the HTTP connection handshake to block Cross-Site WebSocket Hijacking (CSWSH).
- [ ] Require authentication tokens during handshake (e.g., query param or initial token message) before accepting connections.
- [ ] Validate message schema and payload size limits on incoming WebSocket frames.
- [ ] Implement rate limiting per connection to mitigate message flooding.
- [ ] Enforce connection inactivity timeouts and heartbeat monitoring.

---

## 9. Firestore Security Checklist

- [ ] Rule default policy is `allow read, write: if false;` at root level.
- [ ] Collection-specific access rules must require `request.auth != null`.
- [ ] Enforce field schema validation in `firestore.rules` (e.g. `request.resource.data.title is string`).
- [ ] Prevent unauthorized wildcard collection reads (`match /{document=**}`).
- [ ] Audit Firestore indexes and document queries to prevent unintended data leaks across tenant borders.

---

## 10. Prompt Injection Checklist

- [ ] **Direct Injection Check**: Test against common prompt override vectors (`"Ignore previous instructions and..."`).
- [ ] **Indirect Injection Check**: Sanitize third-party content (scraped web pages, news articles, RSS feeds) before feeding into analysis models.
- [ ] **Dual-LLM Verification**: High-risk actions (e.g. deleting resources, sending mass alerts) require secondary safety validator models or human-in-the-loop signoff.
- [ ] **System Prompt Integrity**: Ensure system prompts cannot be extracted or revealed via user queries.

---

## 11. Secrets Management

- [ ] **Zero Hardcoded Secrets**: Absolutely no production keys, database passwords, JWT secrets, or tokens allowed in source code.
- [ ] Use `.env` files locally (never committed, enforced via `.gitignore`).
- [ ] Production secrets must be managed via secret stores (GCP Secret Manager, HashiCorp Vault, environment variables).
- [ ] Automated scanning (`secret_scanner.py`) must pass prior to code merge.
- [ ] Mandatory secret rotation protocol if an API key or token is accidentally exposed.

---

## 12. Dependency Management

- [ ] All dependencies in `requirements.txt` and `package.json` must specify locked/pinned versions.
- [ ] Run `dependency_audit.py` (or `pip-audit` / `npm audit`) in CI/CD pipelines.
- [ ] High or Critical CVE vulnerabilities in dependencies must be resolved within 48 hours.
- [ ] Avoid pulling unmaintained or low-trust packages into the project tree.

---

## 13. Release Security Review

Before tagging any versioned release:
1. Run full security check: `python security/security_check.py --fail-on HIGH`.
2. Confirm zero CRITICAL or HIGH findings exist in reports.
3. Review Firestore security rule changes.
4. Verify environment variable configurations and production deployment manifests.
5. Record release security sign-off in deployment logs.

---

## 14. PR Security Review Process

1. Automated security checks trigger on every Pull Request.
2. If findings exist:
   - PR status check fails.
   - Developer resolves findings or requests a security waiver with documented justification.
3. At least one member of the Security / Tech Lead team must approve any PR touching:
   - `security/` directory
   - `firestore.rules`
   - Authentication / Authorization middleware (`backend/config.py`, `backend/main.py`)
   - AI agent pipeline execution engines (`backend/pipeline.py`, `backend/agents/`)
