# Fix List (Prioritized)

- Generated: 2026-02-21T04:51:22.477271Z
- Total findings: 1

## 1. javascript.lang.security.audit.code-string-concat.code-string-concat: Found data from an Express or Next web request flowing to `eval`. If this data is user-controllable this can lead to execution of arbitrary system commands in the context of your application process. Avoid `eval` whenever possible.
- Tool: `semgrep`
- Severity: **ERROR**
- Location: `app\server.js:26`
- Recommendation: Review code context and apply secure coding fix where applicable.
