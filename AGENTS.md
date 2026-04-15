# Agent Instructions

This file governs how AI agents work on `go-wolfssl`. Read it completely before touching any code.

---

## Beads Workflow

```bash
bd ready                  # find available work (no blockers)
bd show <id>              # read issue details, description, notes, design
bd update <id> --claim    # claim before starting
bd close <id>             # mark complete when done
bd dolt push              # push beads to remote (always at session end)
```

- Use `bd` for ALL task tracking. Never use TodoWrite, markdown TODOs, or in-memory lists.
- Use `bd remember "..."` for persistent facts. Never write MEMORY.md files.
- Run `bd prime` for the full session protocol.

---

## Sources of Truth

Before wrapping any C function, read its header. Always prefer the local copy over
documentation, web search, or memory.

| What you need | Where to look |
|---|---|
| Function signature, parameters, return type | `~/wolfssl/wolfssl/wolfcrypt/<name>.h` |
| Feature preprocessor guards (`HAVE_XXX`, `NO_XXX`) | Same header — look for `#ifdef` around the declaration |
| Error codes (`NOT_COMPILED_IN`, `BAD_FUNC_ARG`, …) | `~/wolfssl/wolfssl/wolfcrypt/error-crypt.h` |
| TLS error codes and `WOLFSSL_SUCCESS` | `~/wolfssl/wolfssl/error-ssl.h` |
| Implementation notes, edge cases, preconditions | `~/wolfssl/wolfcrypt/src/<name>.c` |
| Existing test vectors (wolfSSL's own) | `~/wolfssl/wolfcrypt/test/test.c` |
| TLS/SSL API | `~/wolfssl/wolfssl/ssl.h` |
| Build options compiled into the local install | Run `./generateOptions.sh` → `options.go` |

**Never guess at signatures. Never copy from memory. Read the header.**

---

## Agent Team Pattern

This project uses `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAM` for parallel workstreams.
Set it in the environment before spawning agents:

```bash
export CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAM=1
```

### Standard team for each implementation epic

Spawn all three agents in a single message (parallel launch). Each runs in isolation.

```
┌─────────────────────────────────────────────────┐
│  ORCHESTRATOR  (main context)                   │
│  - reads bd show <id>                           │
│  - spawns team                                  │
│  - reads results                                │
│  - decides: iterate or stop                     │
└───────┬────────────────┬───────────────┬────────┘
        │                │               │
        ▼                ▼               ▼
  IMPLEMENTER      VECTOR-FINDER    HEADER-AUDITOR
  writes Go code   finds RFC/NIST   reads ~/wolfssl
  in isolation     test vectors     confirms sigs,
                   for the algo     guards, errors
```

**IMPLEMENTER subagent** prompt template:
```
Implement Go wrappers for <feature> in go-wolfssl.
Read these files only: <list specific .go and .h files>.
Do not load the whole codebase.
Paranoid defense requirements: [paste checklist from AGENTS.md].
File the result as a patch or edited files.
```

**VECTOR-FINDER subagent** prompt template:
```
Find authoritative test vectors for <algorithm>.
Sources in priority order:
  1. ~/wolfssl/wolfcrypt/test/test.c (wolfSSL's own vectors)
  2. NIST CAVS / ACVTS files in ~/wolfssl/
  3. Relevant RFC (state the RFC number and section)
Do not derive vectors from the implementation under test.
Return vectors as Go []byte literals with source citations.
```

**HEADER-AUDITOR subagent** prompt template:
```
Read ~/wolfssl/wolfssl/wolfcrypt/<header>.h and report:
  1. Exact function signatures for: <list>
  2. Preprocessor guard for each (HAVE_XXX / NO_XXX / always-on)
  3. Required initialization order and ownership rules
  4. Any FIPS-only restrictions noted in comments
  5. Thread safety notes (if any)
Do not write any code.
```

### Review loop

After each implementation pass, spawn a **REVIEWER subagent**:

```
Run ~/PROMPT-review-internaloss.md against the diff in go-wolfssl.
Focus files: <list changed files>.
Read ~/wolfssl headers as needed to verify correctness.
File all findings as beads issues under the parent epic <id>.
```

The orchestrator reads the filed issues and decides:
- **Actionable findings** → spawn IMPLEMENTER to address them, then REVIEWER again
- **Only bikeshedding** (no engineering basis) → stop, close the epic
- **Human decision flagged** → `bd human <id>` and stop

**Never iterate more than 3 rounds on the same finding.** If it is not resolved in 3
passes, escalate with `bd human <id>` rather than retrying.

---

## Paranoid Defensive Programming Checklist

Every wrapper function MUST satisfy all of these. The REVIEWER subagent checks them.

### 1. Return code discipline
- wolfcrypt (`wc_*`): **0 = success**, negative = error. Check with `!= 0`.
- TLS (`wolfSSL_*`): **`WOLFSSL_SUCCESS` (1) = success**, negative/zero = error.
- Never conflate. Never ignore. Never proceed after a non-zero return.
- Propagate the raw C error code to the Go caller — do not swallow it.

### 2. Initialization before use
- Every C struct must be initialized with its `wc_XxxInit()` call before any other
  operation. Passing an uninitialized struct to wolfSSL is undefined behavior.
- Document ownership: who calls Init, who calls Free.

### 3. Paired Init/Free — no leaks
- Every `wc_XxxInit()` must be followed by a deferred or documented `wc_XxxFree()`.
- In Go wrappers that return errors mid-way, free any already-initialized structs before
  returning the error.

### 4. Buffer size validation before C calls
- Validate that output buffers are large enough BEFORE calling into C.
- CGO does not bounds-check. A too-small buffer is a memory corruption bug.
- Use constants from the header (e.g., `WC_SHA256_DIGEST_SIZE`) not magic numbers.
- When the C function writes the actual output length back (e.g., via a `word32*` param),
  validate it against the Go slice length after the call too.

### 5. Key material zeroing
- Use `wc_ForceZero()` (not `memset`, not `bytes.Equal`, not Go's `copy`) to zero
  sensitive buffers before releasing them. The compiler may elide a plain `memset`.
- Zero intermediate key material in error paths, not only in the happy path.

### 6. Null / nil pointer checks
- Check every pointer returned from C for NULL before dereferencing.
- Check every Go slice passed to C is non-nil and non-zero-length where the C API
  requires it (read the header — many functions reject NULL input with `BAD_FUNC_ARG`).

### 7. Conditional compilation stubs
- Every wrapped C function must have a `#else` stub that returns `NOT_COMPILED_IN`
  (-174) or `NULL` when the feature is compiled out.
- Pattern (for an int-returning function):
  ```c
  #ifdef HAVE_FEATURE
    return wc_FeatureDoThing(args);
  #else
    return NOT_COMPILED_IN;
  #endif
  ```
- Pattern (for a pointer-returning function):
  ```c
  #ifdef HAVE_FEATURE
    return wc_FeatureAlloc();
  #else
    return NULL;
  #endif
  ```
- Derive the correct guard from the header — do not guess.

### 8. Zero-length and maximum-size inputs
- Test (or at minimum reason through) behavior for: zero-length input, nil slice,
  max-size input (e.g., 2^31-1 bytes), and mismatched lengths between related args.
- Document any preconditions the C API imposes that the Go wrapper does not enforce.

### 9. Thread safety
- wolfcrypt structs are NOT thread-safe by default. Document this on every exported type.
- If a wrapper function uses global state (e.g., a global RNG), document the concurrency
  contract explicitly.

### 10. FIPS mode compatibility
- Note in comments if a function has FIPS-only restrictions (e.g., minimum key size,
  approved-only mode). Read the header comments and `wc_RunAllCast_fips` test coverage.

### 11. CGO boundary minimalism
- Keep C interop surface minimal. Don't pass Go structs into C; pass primitive types
  and unsafe.Pointer only where unavoidable.
- Never store Go pointers inside C-allocated memory (CGO rule: C code must not hold
  Go pointers after the C call returns).

---

## Non-Interactive Shell Commands

Always use non-interactive flags to avoid hanging:

```bash
cp -f src dst      # not: cp src dst
mv -f src dst      # not: mv src dst
rm -f file         # not: rm file
rm -rf dir         # not: rm -r dir
apt-get install -y # not: apt-get install
```

---

## Implementation Pattern Reference

Every `.go` file in this package follows this structure:

```go
package wolfSSL

// #cgo CFLAGS: -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/wolfcrypt/feature.h>
//
// static int go_wc_FeatureDoThing(FeatureStruct* s, ...) {
// #ifdef HAVE_FEATURE
//     return wc_FeatureDoThing(s, ...);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import "unsafe"
```

- One static C shim per wrapped function (enables the #else stub pattern).
- Return the raw C int; let the caller decide how to interpret it.
- Type aliases: `type FeatureStruct = C.struct_FeatureStruct`

---

## Test Vector Discipline

- **Never use the code under test as its own oracle.**
- Acceptable vector sources (in priority order):
  1. `~/wolfssl/wolfcrypt/test/test.c` — wolfSSL's own CAVS vectors
  2. NIST CAVS/ACVTS published test vectors
  3. RFC appendix vectors (cite RFC number and section)
  4. pyca/cryptography or OpenSSL CLI (cite the exact command)
- Hardcode vectors as `[]byte` literals. Tests must be fully offline.
- VECTOR-FINDER subagent is responsible for sourcing these before IMPLEMENTER writes tests.

---

## Quality Gates (run before closing any epic)

```bash
go vet ./...
go build ./...
go build ./examples/...
```

If `go test` unit tests exist: `go test ./...`

CI workflows: `.github/workflows/build.yml`, `lint.yml`, `test-tls.yml`

---

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
