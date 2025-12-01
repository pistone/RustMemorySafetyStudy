# Rust Memory Safety CVE Study: Overview

## Data Sources and Methodology

This study analyzes 52 memory safety CVEs from the Rust ecosystem between 2023-2025. Data was collected from the RustSec Advisory Database, the National Vulnerability Database (NVD), GitHub Security Advisories, and crate-specific issue trackers. AI tools (Claude) assisted in locating vulnerable code patterns, understanding fix commits, and categorizing vulnerabilities. Each CVE was then manually reviewed to verify the bug mechanism, study the fix, and assess which static analysis checkers could have detected the issue.

## Key Finding

Contrary to common assumptions, **73% of Rust memory safety CVEs occur in pure Rust unsafe code**, not in C FFI bindings (23%). This indicates that unsafe Rust code—not just foreign function interfaces—represents the primary attack surface for memory safety vulnerabilities.

| Category | Count | Percentage |
|----------|-------|------------|
| Pure Rust Unsafe Code | 38 | 73% |
| C Library FFI Bindings | 12 | 23% |
| System Call Wrappers / Kernel | 2 | 4% |

## Proposed Checkers

Based on the CVE analysis, we propose three new checker categories where existing tools have limited coverage, plus extensions to our existing taint analysis framework.

### 1. NULL_RETURN for Unsafe Code

This checker detects cases where C functions called from unsafe Rust code may return NULL, but the return value is used without validation. Six CVEs in rust-ffmpeg alone (CVE-2025-57611 through CVE-2025-57616) stem from this pattern—functions like `avfilter_graph_dump()` and `av_get_sample_fmt_name()` return NULL on failure, but the Rust wrapper immediately dereferences the result via `CStr::from_ptr()`. See the rust-ffmpeg examples in the C Library FFI Bindings section for reference.

**Why existing checkers miss this:** Traditional NULL_RETURN checkers flag missing NULL checks in C/C++ code. However, in Rust FFI code, the NULL pointer is often passed through unsafe pointer casts or wrapped in safe-looking abstractions before dereference. Our checker would track NULL-returning C functions through Rust's unsafe boundaries.

### 2. WRITE_IMMUTABLE for Unsafe Code

This checker detects when code holding a shared reference (`&T`) modifies the referenced data through raw pointers, violating Rust's aliasing guarantees. The `&self` pattern is one common instance, but the issue applies to any immutable reference. CVE-2023-30624 (Wasmtime) and CVE-2025-57616 (rust-ffmpeg `write_interleaved`) exemplify this: code with only shared access internally mutates state through `unsafe` pointer operations. LLVM optimizes based on Rust's `noalias readonly` semantics, assuming data behind shared references doesn't change—when it does, the result is undefined behavior that manifests as miscompilation.

**Why existing checkers miss this:** Rust's borrow checker validates safe code but cannot see through raw pointer operations in unsafe blocks. C/C++ analyzers don't understand Rust's reference semantics. Our checker would identify unsafe blocks that perform writes through raw pointers when only a shared reference (`&T`) is held to that data.

### 3. INTEGER_OVERFLOW for Safe and Unsafe Code

This checker detects integer overflow in size calculations, particularly when values cross API boundaries (e.g., `usize` to `c_int`). CVE-2023-22895 (bzip2) demonstrates truncation when a 64-bit buffer length is cast to 32-bit `c_uint`, causing infinite loops for buffers exceeding 4GB. CVE-2025-57614 and CVE-2025-57615 (rust-ffmpeg) show `u32` dimensions wrapping to negative values when cast to `c_int`. See the Integer Overflow section for detailed patterns.

**Why existing checkers miss this:** Standard overflow checkers focus on arithmetic operations within a single type. These vulnerabilities occur at type boundaries—especially Rust's unsigned types converting to C's signed types. Our checker would flag narrowing casts of untrusted or large values at FFI boundaries.

### 4. Taint Analysis Extensions

Multiple CVEs involve untrusted input flowing to dangerous operations: array indices (CVE-2023-53161, CVE-2023-53160), memory allocation sizes (CVE-2024-43410, CVE-2023-39410), and buffer lengths (CVE-2023-50711). Our existing taint analysis framework covers these patterns; the CVE data validates their importance and may inform additional sink definitions.

## Business Case

The Rust ecosystem is growing rapidly in security-critical domains (cloud infrastructure, WebAssembly runtimes, cryptographic libraries). Our analysis shows that 38 of 52 CVEs (73%) occur in pure Rust unsafe code where traditional C/C++ checkers lack visibility and Rust's compiler provides no protection. By targeting NULL_RETURN, WRITE_IMMUTABLE, and INTEGER_OVERFLOW specifically in unsafe Rust contexts, we address a gap that neither Rust's safety guarantees nor existing static analyzers cover effectively.
