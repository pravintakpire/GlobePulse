# GlobePulse Architecture Security Analysis & Threat Model

## Executive Summary

GlobePulse is a global real-time news, intelligence, and event tracking platform. It leverages a modern hybrid architecture comprising a **FastAPI backend service**, **Vite/React TypeScript frontend**, **Firebase Firestore NoSQL database**, **Databricks data pipeline**, and **Google Gemini AI integration** for automated news synthesis and agentic workflows.

This document provides a comprehensive security architecture review, threat model analysis, attack surface assessment, and recommended security enhancements.

---

## Architecture Security Overview

```
                      +-----------------------------+
                      |   Client Web Application    |
                      |  (Vite / React TypeScript)  |
                      +-----------------------------+
                                     |
                         HTTPS / WSS / Firestore SDK
                                     |
        +----------------------------+----------------------------+
        |                                                         |
        v                                                         v
+-------------------------+                           +-----------------------+
|  FastAPI Backend Engine |                           |   Firebase Firestore  |
|  (Python 3.12 / REST)   |                           |    (NoSQL Database)   |
+-------------------------+                           +-----------------------+
        |                                                         ^
        +------------+                                            |
                     |                                            |
                     v                                            |
+------------------------------------+                            |
| Databricks & Gemini AI Agents      |----------------------------+
| (Pipeline & Article Processing)    |
+------------------------------------+
```

---

## Component Security Analysis & Attack Surface

### 1. Backend REST API (`backend/main.py`, `backend/config.py`)
- **Technology**: FastAPI / Python 3.12
- **Attack Surface**: Public REST endpoints (`/api/...`), configuration files, CORS policies, environment variable handling.
- **Identified Risk Vectors**:
  - Unvalidated incoming query parameters in API endpoints leading to injection or SSRF.
  - Wildcard CORS settings (`allow_origins=["*"]`) in local configuration if propagated to production.
  - Unhandled application exceptions potentially leaking stack traces or internal environment variables.

### 2. Firebase Firestore Database (`firestore.rules`, `backend/database.py`)
- **Technology**: Cloud Firestore NoSQL
- **Attack Surface**: Client-side Firestore SDK connections, document read/write rules.
- **Identified Risk Vectors**:
  - Overly permissive security rules (`allow read, write: if true;` or unauthenticated collection reads).
  - Lack of document field schema validation allowing clients to write malformed or malicious payloads.
  - IDOR (Insecure Direct Object Reference) vulnerabilities if document access is not validated against `request.auth.uid`.

### 3. Gemini AI Agentic Pipeline (`backend/pipeline.py`, `backend/agents/`)
- **Technology**: Google Gemini Pro / Flash API, Python agentic pipeline
- **Attack Surface**: Input news articles, user prompt templates, tool execution routines.
- **Identified Risk Vectors**:
  - **Prompt Injection**: Maliciously formatted news articles or prompt payloads designed to hijack LLM instruction flow.
  - **System Prompt Extraction**: Exposure of internal system instructions through crafted inputs.
  - **Unsanitized Output Rendering**: Executing or rendering LLM output directly without sanitization or HTML escaping.
  - **API Key Handling**: Exposure of `GEMINI_API_KEY` in source code or client-side bundles.

### 4. Frontend Web Client (`frontend/src/`)
- **Technology**: Vite, React, TypeScript, TailwindCSS
- **Attack Surface**: Web UI inputs, API clients, state management, static asset rendering.
- **Identified Risk Vectors**:
  - DOM-based Cross-Site Scripting (DOM XSS) if external article contents or titles are rendered directly into HTML without escaping.
  - Insecure storage of authentication tokens or user state in browser LocalStorage.
  - Supply chain dependencies in `package.json`.

---

## Threat Model (STRIDE Assessment)

| Threat Category | GlobePulse Vector | Mitigation Strategy |
| :--- | :--- | :--- |
| **Spoofing** | Unauthenticated user spoofing requests to FastAPI backend or Firestore | Enforce Firebase Auth JWT verification on all non-public API endpoints and Firestore rules. |
| **Tampering** | Modification of pipeline articles or Firestore news records | Enforce server-side write permissions, input schema validation, and digital signatures for data pipeline ingests. |
| **Repudiation** | Actions performed by AI agents or users without audit logging | Implement audit logging for all critical operations (article publishing, source modifications, admin actions). |
| **Information Disclosure** | Leakage of `GEMINI_API_KEY`, database credentials, or internal stack traces | Enforce `secret_scanner.py` pre-commit hooks, mask sensitive logs, scrub API responses. |
| **Denial of Service** | Resource exhaustion via unthrottled API calls, WebSocket flooding, or heavy Gemini API queries | Implement rate limiting (e.g. Slowapi) on REST endpoints and budget caps on Gemini API usage. |
| **Elevation of Privilege** | Normal user escalating to admin or bypassing AI tool execution bounds | Server-side role verification (RBAC), strict tool whitelisting in Gemini agent invocations. |

---

## Baseline Security Findings & Recommendations

### Immediate Action Items
1. **Automated Scanner Deployment**: Execute `python security/security_check.py` on every local commit and CI build.
2. **Firestore Rules Enforcement**: Audit `firestore.rules` to ensure default-deny policies and authentication enforcement.
3. **LLM Input Isolation**: Wrap raw article texts and user queries inside structural XML tags (e.g. `<article_text>...</article_text>`) before sending prompts to Gemini.
4. **Secret Scanning**: Verify `.gitignore` covers `.env`, GCP credentials, and local service account keys.

---

## Long-term Security Roadmap

- **Phase 1 (Current)**: Implement automated security checks (`security/`), secret scanning, dependency auditing, and pre-commit hooks.
- **Phase 2**: Add API rate limiting, CSP (Content Security Policy) headers to Vite/FastAPI, and automated dependency updates via Dependabot/Renovate.
- **Phase 3**: Implement dynamic application security testing (DAST) in staging environment and set up GCP Secret Manager integration for production deployment.
