# Security Audit Report

**Repository:** WhisperCode (fork of OpenCode)
**Date:** 2026-03-09
**Auditor:** Automated security scan

## Summary

**Verdict: SAFE TO USE**

This repository is a legitimate fork of [OpenCode](https://github.com/anomalyco/opencode), an open-source AI-powered coding tool, with added iOS/Android mobile support. No malicious code, backdoors, or data exfiltration patterns were found.

## Audit Checklist

### 1. Reverse Shells / Backdoors
- **Status:** CLEAN
- No reverse shell patterns, no hardcoded malicious IPs, no socket connections to unknown hosts
- All IP addresses found are standard loopback (`127.0.0.1`, `0.0.0.0`, `::1`) used for local dev servers

### 2. Obfuscated / Eval Code
- **Status:** CLEAN (minor note)
- One `new Function()` usage in `packages/opencode/src/cli/cmd/debug/agent.ts:99` — this is a CLI debug command that parses user-provided `--params` as a JS object literal fallback after JSON parsing fails. This is local-only, user-initiated, and acceptable for a CLI tool
- No obfuscated variable names, no hex-encoded payloads, no suspicious `String.fromCharCode` chains

### 3. Data Exfiltration / Credential Harvesting
- **Status:** CLEAN
- `dataDumper.ts` — despite the suspicious name, this is a server-side production analytics logger that only runs in their cloud (`Resource.App.stage !== "production"` guard). It logs API request/response metadata to their own S3 buckets. It does NOT run locally
- No code reads SSH keys, `.env` files, `/etc/passwd`, AWS credentials, or similar sensitive data
- No code transmits environment variables to external servers

### 4. Install Scripts & Lifecycle Hooks
- **Status:** CLEAN
- **Root `package.json`:** `"prepare": "husky"` — standard husky setup
- **Husky pre-push hook:** Only runs `bun typecheck` — safe
- **`script/hooks`:** Installs a git pre-push hook that runs `bun install` and `bun run typecheck` — safe
- **`install` script:** Standard bash installer that downloads releases from `github.com/anomalyco/opencode` — legitimate
- **VSCode extension:** `"vscode:prepublish": "bun run package"` — standard for VS Code extensions
- No `preinstall` or `postinstall` scripts that execute suspicious commands

### 5. Dependencies
- **Status:** CLEAN
- All dependencies are well-known, widely-used packages (SolidJS, Hono, Drizzle, Tailwind, Vite, etc.)
- `trustedDependencies` list includes only standard native packages: `esbuild`, `protobufjs`, `tree-sitter`, `electron`
- No unknown or suspiciously-named packages

### 6. Cryptocurrency Miners
- **Status:** CLEAN
- No references to mining pools, crypto wallets, hashrate, xmrig, coinhive, or Monero

### 7. Network Calls
- **Status:** CLEAN
- All `fetch()` and HTTP calls are to legitimate API endpoints (AI providers like Anthropic/OpenAI/Google, GitHub API, their own API)
- No calls to unknown or suspicious domains

### 8. GitHub Actions / CI
- **Status:** CLEAN
- Standard CI/CD workflows for testing, building, releasing, and deploying
- No workflows that exfiltrate secrets or run untrusted code

### 9. File System Abuse
- **Status:** CLEAN
- No code writes to system directories, modifies PATH maliciously, or creates cron jobs
- The `install` script writes only to `~/.opencode/bin/` and appends PATH to shell config — standard behavior

### 10. Hidden Files / Directories
- **Status:** CLEAN
- `.opencode/` — configuration directory for the OpenCode tool (agents, commands, themes, tools)
- `.husky/` — standard git hooks
- `.github/` — standard GitHub Actions workflows
- `.signpath/` — code signing configuration
- No suspicious hidden files

## Notes

- The `packages/opencode/src/util/scrap.ts` file contains placeholder/dead code (`foo`, `bar`, `dummyFunction`, `randomHelper`). Harmless but could be cleaned up
- `base64` usage throughout is for legitimate image encoding, git authentication, and API communication
- `child_process` usage is expected and appropriate for a CLI/desktop application (shell execution, LSP servers, git operations)

## Conclusion

This repository is safe to clone, install dependencies for, and run locally. It is a well-structured TypeScript monorepo with standard open-source tooling. No indicators of malicious intent were found.
