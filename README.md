# Rust Memory Safety CVE Analysis (2023-2025)

## Overview

This document analyzes 52 memory safety CVEs from the Rust ecosystem between 2023-2025, categorizing them based on whether they involve **C library FFI bindings** (unsafe Rust wrapping C/C++ libraries) or **pure Rust unsafe code** (no C FFI, internal unsafe blocks only).

---

## Summary Statistics

| Category | Count | Percentage |
|----------|-------|------------|
| **C Library FFI Bindings** | 12 | 23% |
| **Pure Rust Unsafe Code** | 38 | 73% |
| **System Call Wrappers / Kernel** | 2 | 4% |
| **Total** | 52 | 100% |

---

## Category 1: C Library FFI Bindings

These CVEs occur in Rust crates that are FFI wrappers around C/C++ libraries. The vulnerabilities stem from the interaction between Rust's unsafe code and underlying C code.

| CVE | Crate | C Library | Vulnerability Type |
|-----|-------|-----------|-------------------|
| **CVE-2025-57616** | rust-ffmpeg | FFmpeg (C) | Use-after-free in `write_interleaved` |
| **CVE-2025-57615** | rust-ffmpeg | FFmpeg (C) | Integer overflow in `Vector::new` |
| **CVE-2025-57614** | rust-ffmpeg | FFmpeg (C) | Integer overflow in `cached` |
| **CVE-2025-57613** | rust-ffmpeg | FFmpeg (C) | Null pointer dereference in `input()` |
| **CVE-2025-57612** | rust-ffmpeg | FFmpeg (C) | Null pointer dereference in `name()` |
| **CVE-2025-57611** | rust-ffmpeg | FFmpeg (C) | Null pointer dereference in `dump()` |
| **CVE-2025-3416** | rust-openssl | OpenSSL (C) | Use-after-free in properties handling |
| **CVE-2025-24898** | rust-openssl | OpenSSL (C) | Lifetime/dangling pointer in `select_next_proto` |
| **CVE-2024-27284** | cassandra-rs | DataStax C++ Driver | Use-after-free from iterator invalidation |
| **CVE-2024-52296** | libosdp | LibOSDP (C) | Out-of-bounds read in `osdp_reply_name` |
| **CVE-2024-52288** | libosdp | LibOSDP (C) | Buffer-related issue with `REPLY_CCRYPT` |
| **CVE-2023-53159** | openssl (crate) | OpenSSL (C) | Out-of-bounds read in `X509VerifyParamRef::set_host` |

### Common Patterns in C FFI Vulnerabilities

1. **Missing NULL checks**: The rust-ffmpeg vulnerabilities are specifically caused by unsafe code calling FFmpeg C functions without properly checking for NULL return values.

2. **Iterator invalidation mismatch**: The cassandra-rs vulnerability occurred because the underlying C driver invalidates the current iterator item when `next()` is called, but this semantic was not reflected in the Rust binding.

3. **Lifetime assumptions**: The rust-openssl vulnerability in `select_next_proto` returns a slice pointing into the server argument's buffer but with an incorrect lifetime.

### Detailed Code Examples for C FFI Vulnerabilities

#### rust-ffmpeg: CVE-2025-57611 (Null Pointer Dereference in `dump()`)

```rust
// VULNERABLE: src/filter/graph.rs:97
pub fn dump(&self) -> String {
    unsafe {
        let ptr = avfilter_graph_dump(self.as_ptr() as *mut _, ptr::null());
        // BUG: No NULL check! avfilter_graph_dump() returns NULL on failure
        // (e.g., memory allocation failure)
        let cstr = from_utf8_unchecked(CStr::from_ptr(ptr).to_bytes());
        let string = cstr.to_owned();
        av_free(ptr as *mut _);
        string
    }
}

// FIXED: Check for NULL before use
pub fn dump(&self) -> String {
    unsafe {
        let ptr = avfilter_graph_dump(self.as_ptr() as *mut _, ptr::null());
        if ptr.is_null() {
            return String::new(); // or return Err(...)
        }
        let cstr = CStr::from_ptr(ptr);
        let string = cstr.to_string_lossy().into_owned();
        av_free(ptr as *mut _);
        string
    }
}
```
This one is NULL_RETURN. 
#### rust-ffmpeg: CVE-2025-57612 (Null Pointer Dereference in `name()`)

```rust
// VULNERABLE: src/util/format/sample.rs:37
#[inline]
pub fn name(&self) -> &'static str {
    unsafe {
        from_utf8_unchecked(
            // BUG: av_get_sample_fmt_name() returns NULL for unrecognized formats
            // (e.g., AV_SAMPLE_FMT_NONE), but we pass it directly to CStr::from_ptr
            CStr::from_ptr(av_get_sample_fmt_name((*self).into()))
                .to_bytes(),
        )
    }
}

// FIXED: Return Option to handle unrecognized formats
#[inline]
pub fn name(&self) -> Option<&'static str> {
    unsafe {
        let ptr = av_get_sample_fmt_name((*self).into());
        if ptr.is_null() {
            return None;
        }
        Some(from_utf8_unchecked(CStr::from_ptr(ptr).to_bytes()))
    }
}
```
NULL_RETURN
#### rust-ffmpeg: CVE-2025-57613 (Null Pointer Dereference in `input()`)

```rust
// VULNERABLE: src/format/io.rs:152
pub fn input(value: impl Read + Seek + 'static) -> Self {
    unsafe {
        let proxy = Box::into_raw(Box::new(Proxy::Input(Box::new(value))));
        let ptr = avio_alloc_context(
            ptr::null_mut(),
            0,
            AVIO_FLAG_READ & AVIO_FLAG_DIRECT,
            proxy.cast(),
            Some(read_packet),
            None,
            Some(seek),
        );
        // BUG: ptr could be NULL on allocation failure!
        // Drop will dereference this NULL pointer
        Io { proxy, ptr }
    }
}

// FIXED: Return Result and handle allocation failure
pub fn input(value: impl Read + Seek + 'static) -> Result<Self, String> {
    unsafe {
        let proxy = Box::into_raw(Box::new(Proxy::Input(Box::new(value))));
        let ptr = avio_alloc_context(
            ptr::null_mut(),
            0,
            AVIO_FLAG_READ & AVIO_FLAG_DIRECT,
            proxy.cast(),
            Some(read_packet),
            None,
            Some(seek),
        );
        if ptr.is_null() {
            // Clean up proxy to avoid memory leak
            let _ = Box::from_raw(proxy);
            return Err("avio_alloc_context failed (likely out of memory)".to_string());
        }
        Ok(Io { proxy, ptr })
    }
}
```
NULL_RETURN
#### rust-ffmpeg: CVE-2025-57614 (Integer Overflow in `cached()`)

```rust
// VULNERABLE: src/software/scaling/context.rs:106
pub fn cached(
    &mut self,
    src_format: format::Pixel,
    src_w: u32,  // Takes u32
    src_h: u32,
    dst_format: format::Pixel,
    dst_w: u32,
    dst_h: u32,
    flags: Flags,
) {
    // ...
    unsafe {
        self.ptr = sws_getCachedContext(
            self.as_mut_ptr(),
            src_w as c_int,  // BUG: Cast wraps on values > i32::MAX
            src_h as c_int,  // producing negative dimensions
            src_format.into(),
            dst_w as c_int,
            dst_h as c_int,
            dst_format.into(),
            flags.bits(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
        );
    }
}

// Trigger example - safe Rust code causing UB:
let huge = i32::MAX as u32 + 1; // 2147483648
scaler.cached(
    format::Pixel::YUV420P,
    huge,  // wraps to -2147483648 when cast to c_int
    1080,
    format::Pixel::RGBA,
    1280,
    720,
    Flags::BILINEAR,
);

// FIXED: Validate dimensions before casting
pub fn cached(&mut self, /* ... */) {
    if src_w == 0 || src_h == 0 || dst_w == 0 || dst_h == 0 {
        panic!("All dimensions must be positive");
    }
    if src_w > i32::MAX as u32 || src_h > i32::MAX as u32 
       || dst_w > i32::MAX as u32 || dst_h > i32::MAX as u32 {
        panic!("Dimension exceeds i32::MAX");
    }
    // ... safe to proceed with cast
}
```
INTEGER_OVERFLOW
#### rust-ffmpeg: CVE-2025-57615 (Integer Overflow in `Vector::new()`)

```rust
// VULNERABLE: src/software/scaling/vector.rs:36
pub fn new(length: usize) -> Self {
    unsafe {
        Vector {
            // BUG: usize can be larger than i32::MAX
            // When length > i32::MAX, cast wraps to negative value
            ptr: sws_allocVec(length as c_int),
            _own: true,
            _marker: PhantomData,
        }
    }
}

// Trigger example:
let vec = Vector::new(std::i32::MAX as usize + 1);
// length becomes -2147483648 when cast to c_int
// C function receives invalid parameter, returns NULL
// Subsequent operations dereference NULL

// FIXED: Validate length before casting
pub fn new(length: usize) -> Self {
    if length > i32::MAX as usize {
        panic!("Length {} exceeds i32::MAX", length);
    }
    unsafe {
        let ptr = sws_allocVec(length as c_int);
        if ptr.is_null() {
            panic!("sws_allocVec allocation failed");
        }
        Vector { ptr, _own: true, _marker: PhantomData }
    }
}
```
INTEGER_OVERFLOW NULL_RETURN
#### rust-ffmpeg: CVE-2025-57616 (Use-After-Free in `write_interleaved()`)

```rust
// VULNERABLE: src/codec/packet/packet.rs:236
#[inline]
pub fn write_interleaved(&self, format: &mut format::context::Output) -> Result<bool, Error> {
    unsafe {
        if self.is_empty() {
            return Err(Error::InvalidData);
        }
        // BUG: Method takes &self (immutable borrow) but av_interleaved_write_frame
        // MUTATES and CLEARS the packet. This violates Rust's aliasing rules.
        match av_interleaved_write_frame(format.as_mut_ptr(), self.as_mut_ptr()) {
            1 => Ok(true),
            0 => Ok(false),
            e => Err(Error::from(e)),
        }
    }
}

// FIXED: Take &mut self to reflect mutation
#[inline]
pub fn write_interleaved(&mut self, format: &mut format::context::Output) -> Result<bool, Error> {
    unsafe {
        if self.is_empty() {
            return Err(Error::InvalidData);
        }
        match av_interleaved_write_frame(format.as_mut_ptr(), self.as_mut_ptr()) {
            1 => Ok(true),
            0 => Ok(false),
            e => Err(Error::from(e)),
        }
    }
}
```
A new checker: MUTATE_IMMUTABLE - clippy has lint rules in this category but is said not to be able to catch this one. For us, our deriver should be able to know that the second parameter of av_interleaved_write_frame is written.
#### rust-openssl: CVE-2025-24898 (Use-After-Free in `select_next_proto()`)

```rust
// VULNERABLE: The function returns a slice pointing into `server` buffer
// but with lifetime bound to `client` argument
pub fn select_next_proto<'a>(server: &[u8], client: &'a [u8]) -> Option<&'a [u8]> {
    // ... returns slice from server but lifetime is 'a (from client)
}

// NOT VULNERABLE - server buffer has 'static lifetime:
builder.set_alpn_select_callback(|_, client_protos| {
    ssl::select_next_proto(b"\x02h2", client_protos).ok_or_else(AlpnError::NOACK)
});

// NOT VULNERABLE - server buffer outlives the handshake:
let server_protos = b"\x02h2".to_vec();
builder.set_alpn_select_callback(|_, client_protos| {
    ssl::select_next_proto(&server_protos, client_protos).ok_or_else(AlpnError::NOACK)
});

// VULNERABLE - server buffer is freed when callback returns:
builder.set_alpn_select_callback(|_, client_protos| {
    let server_protos = b"\x02h2".to_vec();  // Temporary, freed at end of closure
    ssl::select_next_proto(&server_protos, client_protos)  // Returns dangling pointer!
        .ok_or_else(AlpnError::NOACK)
});

// FIXED (openssl 0.10.70): Constrain output lifetime to BOTH inputs
pub fn select_next_proto<'a>(server: &'a [u8], client: &'a [u8]) -> Option<&'a [u8]> {
    // Now the returned slice cannot outlive the server buffer
}
```

#### cassandra-rs: CVE-2024-27284 (Iterator Invalidation)

```rust
// VULNERABLE (cassandra-rs < 3.0): Standard Iterator implementation
// The underlying C driver invalidates the current item when next() is called,
// but Rust's Iterator trait doesn't express this constraint

impl Iterator for ResultIterator {
    type Item = Row;
    
    fn next(&mut self) -> Option<Self::Item> {
        // BUG: After calling next(), the previous Row is INVALIDATED by the C driver
        // but Rust allows keeping references to it
        unsafe {
            if cass_iterator_next(self.inner) {
                Some(Row::from_raw(cass_iterator_get_row(self.inner)))
            } else {
                None
            }
        }
    }
}

// Usage that triggers UB (safe Rust code!):
let mut iter = result.iter();
let row1 = iter.next().unwrap();  // Get first row
let row2 = iter.next().unwrap();  // C driver invalidates row1!
println!("{}", row1);              // Use-after-free! row1 points to invalid memory

// FIXED (cassandra-rs 3.0): Use LendingIterator trait
// Iterators no longer implement std::iter::Iterator
// Instead, they implement a custom LendingIterator trait that correctly
// models the C driver's invalidation semantics

pub trait LendingIterator {
    type Item<'a> where Self: 'a;
    fn next(&mut self) -> Option<Self::Item<'_>>;
}

impl LendingIterator for ResultIterator {
    type Item<'a> = Row<'a>;  // Lifetime tied to iterator borrow
    
    fn next(&mut self) -> Option<Self::Item<'_>> {
        // Now Row's lifetime is tied to the &mut self borrow
        // Calling next() again requires exclusive access, preventing use-after-free
    }
}
```
Not sure if we can catch this one.
#### libosdp: CVE-2024-52296 (Null Pointer Dereference in `osdp_reply_name()`)

```c
// VULNERABLE C code in osdp_common.c
// The Rust crate (libosdp) wraps this C library

static const char *names[] = {
    [REPLY_ACK - REPLY_ACK] = "osdp_ACK",
    [REPLY_NAK - REPLY_ACK] = "osdp_NAK",
    // ... but not all reply IDs have entries!
    // Some slots are implicitly NULL
};

const char *osdp_reply_name(int reply_id) {
    const char *name;
    
    // Any reply_id between REPLY_ACK and REPLY_XRD is valid
    if (reply_id < REPLY_ACK || reply_id > REPLY_XRD) {
        return NULL;
    }
    
    name = names[reply_id - REPLY_ACK];  // Could be NULL for undefined IDs!
    
    // BUG: Dereferences NULL if reply_id lacks corresponding entry
    if (name[0] == '\0') {  // CRASH: null[0] is invalid
        return NULL;
    }
    return name;
}

// The Rust wrapper (libosdp crate) calls this function without additional checks,
// exposing the null pointer dereference to Rust users

// FIXED: Check for NULL before dereferencing
const char *osdp_reply_name(int reply_id) {
    if (reply_id < REPLY_ACK || reply_id > REPLY_XRD) {
        return NULL;
    }
    const char *name = names[reply_id - REPLY_ACK];
    if (name == NULL || name[0] == '\0') {  // Added NULL check
        return NULL;
    }
    return name;
}
```

---
CANNOT be checked.
## Category 2: Pure Rust Unsafe Code

These CVEs occur in crates written entirely in Rust, where the vulnerability is in unsafe Rust code that doesn't involve C bindings.

### Concurrency / Data Race Issues

| CVE | Crate | Vulnerability Type |
|-----|-------|-------------------|
| **CVE-2025-4574** | crossbeam-channel | Double-free in `Drop` due to race condition |
| **CVE-2025-48753** | anode | Data races in `unlock` in SpinLock |
| **CVE-2025-48751** | process_lock | Data races in unlock |
| **CVE-2025-48752** | process-sync | Missing check for pthread_mutex unlock state |
| **CVE-2025-47735** | wgp | Missing `drop_slow` thread synchronization |
| **CVE-2024-27308** | Mio | Invalid tokens for Windows named pipes |
| **CVE-2023-22466** | Tokio | Windows named pipe server produces invalid tokens |

#### Code Example: crossbeam-channel Double-Free (CVE-2025-4574)

```rust
// SIMPLIFIED illustration of the race condition pattern
// The actual bug involved complex atomic operations in the unbounded channel

// The vulnerability occurred in the Drop implementation
impl<T> Drop for Channel<T> {
    fn drop(&mut self) {
        // Thread 1 and Thread 2 might both execute this concurrently
        
        // Original buggy pattern (simplified):
        let tail = self.tail.load(Ordering::Acquire);
        
        // RACE WINDOW: Between load and swap, another thread might
        // have already processed and freed this block
        
        if !tail.is_null() {
            // BUG: A PR fixing a memory leak changed only ONE of the loads
            // to a swap operation, creating asymmetry that enabled double-free
            let block = self.tail.swap(ptr::null_mut(), Ordering::AcqRel);
            
            // If another thread already freed this block, we have UAF
            unsafe { drop(Box::from_raw(block)); }  // DOUBLE-FREE!
        }
    }
}

// The fix involved ensuring proper synchronization of the tail pointer
// access across all code paths in the Drop implementation
```

#### Code Example: SpinLock Data Race (CVE-2025-48753 - anode)

```rust
// VULNERABLE: Unsound SpinLock implementation
pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}  // BUG: Missing proper bounds

impl<T> SpinLock<T> {
    pub fn unlock(&self) {
        // BUG: No memory barrier before releasing the lock
        // Another thread might see stale data
        self.locked.store(false, Ordering::Relaxed);  // Should be Release!
    }
}

// FIXED: Use proper memory ordering
impl<T> SpinLock<T> {
    pub fn unlock(&self) {
        // Release ordering ensures all writes are visible before unlock
        self.locked.store(false, Ordering::Release);
    }
}
```

### WebAssembly Runtime (Wasmtime)

| CVE | Crate | Vulnerability Type |
|-----|-------|-------------------|
| **CVE-2025-64345** | Wasmtime | Unsound interaction with WebAssembly shared linear memory |
| **CVE-2025-61670** | Wasmtime | Memory leaks in C/C++ API for anyref/externref |
| **CVE-2024-47763** | Wasmtime | Runtime crash from tail calls + stack traces |
| **CVE-2023-30624** | Wasmtime | LLVM-level undefined behavior in per-instance state |

#### Code Example: Wasmtime LLVM-Level UB (CVE-2023-30624)

```rust
// VULNERABLE: Methods take &self but modify VMContext data
// LLVM assumes &self methods don't modify data (noalias readonly)

impl Instance {
    // Takes &self (shared reference)
    pub fn get_export(&self, name: &str) -> Option<Extern> {
        // BUG: Internally modifies VMContext data through raw pointers
        // This violates LLVM's aliasing assumptions
        unsafe {
            let vmctx = self.vmctx_ptr();
            // Modification through raw pointer bypasses Rust's borrow checker
            // but LLVM's optimizer assumes this data is readonly
            (*vmctx).some_field = new_value;  // UB!
        }
        // ...
    }
}

// The optimizer might:
// 1. Reorder reads/writes assuming no aliasing
// 2. Cache values assuming they don't change
// 3. Eliminate "redundant" loads that were actually observing mutations

// FIXED: Use interior mutability or &mut self
impl Instance {
    // Option 1: Use Cell/RefCell for interior mutability
    pub fn get_export(&self, name: &str) -> Option<Extern> {
        // Uses Cell<T> for fields that need mutation
        self.vmctx.some_field.set(new_value);  // Valid interior mutability
    }
    
    // Option 2: Take &mut self if mutation is required
    pub fn get_export_mut(&mut self, name: &str) -> Option<Extern> {
        self.vmctx.some_field = new_value;  // Valid with exclusive access
    }
}
```
This is similar to the MUTATE_IMMUTABLE checker above.

The other three: one cannot be found. Another is shared memory -> &[u8] -> memory. The third is unexpected stack frame but only conceptual description is found.

### Buffer Overflow / Out-of-Bounds

| CVE | Crate | Vulnerability Type |
|-----|-------|-------------------|
| **CVE-2023-50711** | vmm-sys-util | Buffer overflow in `FamStructWrapper::deserialize` |
| **CVE-2023-28448** | Versionize | Out-of-bounds read/write in `FamStructWrapper` |
| **CVE-2023-41051** | vm-memory | Out-of-bounds write accessing VM physical memory |
| **CVE-2023-53161** | buffered-reader | Out-of-bounds array access |
| **CVE-2023-53160** | sequoia-openpgp | Out-of-bounds array access |
| **CVE-2023-42444** | phonenumber | Panic-guarded out-of-bounds access |
| **CVE-2024-39697** | phonenumber | Out-of-bounds access on phonenumber string |
| **CVE-2024-51502** | loona-hpack | Same vulnerability as hpack issue #11 |
| **CVE-2023-28445** | Deno | Resizable ArrayBuffers shrunk during async operation |
| **CVE-2023-3036** | cfnts | Panic from out-of-bounds read |

Some can be checked with TAINTED analysis. A detailed analysis can be found in [See more details](./overunanalysis.md).

#### Code Example: FamStructWrapper Buffer Overflow (CVE-2023-50711)

```rust
// VULNERABLE: Deserialization doesn't validate array length against capacity
pub struct FamStructWrapper<T: FamStruct> {
    // Fixed-size header followed by variable-length array
    mem: Vec<u8>,
}

impl<T: FamStruct> FamStructWrapper<T> {
    pub fn deserialize(reader: &mut impl Read) -> Result<Self> {
        let mut header = T::default();
        reader.read_exact(header.as_mut_slice())?;
        
        // BUG: Reads array length from untrusted input
        let count = header.len();  // Attacker-controlled!
        
        // Allocates based on untrusted length without bounds checking
        let mut wrapper = Self::new(count)?;
        
        // Reads potentially more data than allocated
        reader.read_exact(wrapper.as_mut_fam_slice())?;  // Buffer overflow!
        
        Ok(wrapper)
    }
}

// FIXED: Validate length before allocation and read
impl<T: FamStruct> FamStructWrapper<T> {
    pub fn deserialize(reader: &mut impl Read, max_count: usize) -> Result<Self> {
        let mut header = T::default();
        reader.read_exact(header.as_mut_slice())?;
        
        let count = header.len();
        
        // Bounds check against maximum allowed size
        if count > max_count {
            return Err(Error::InvalidLength);
        }
        
        let mut wrapper = Self::new(count)?;
        reader.read_exact(wrapper.as_mut_fam_slice())?;
        
        Ok(wrapper)
    }
}
```
This part of failure can be detected with a TAINTED analysis. But looking further we found the root cause of overrun.

```rust
impl<T: FamStruct> FamStructWrapper<T> {
    /// Returns the entries as a slice.
    /// 
    /// SAFETY: This is safe because we maintain the invariant that
    /// `header.len()` always equals the actual number of allocated entries.
    pub fn as_slice(&self) -> &[T::Entry] {
        let header = self.as_fam_struct_ref();
        let count = header.len();  // ← Length from header (trusted?)
        
        unsafe {
            let entries_ptr = self.mem.as_ptr()
                .add(std::mem::size_of::<T>())  // Skip header
                as *const T::Entry;
            
            // Create slice with `count` elements
            std::slice::from_raw_parts(entries_ptr, count)
            //                                      ^^^^^
            //                                      If count > actual allocation,
            //                                      this creates an invalid slice
        }
    }
}
```
Now an overrun happens when count mismatches entries_ptr's size. Unfortunately current OVERRUN does not have this capability.


#### Code Example: Deno ArrayBuffer Shrink (CVE-2023-28445)

```rust
// VULNERABLE: ArrayBuffer can be resized during async operation
async fn read_into_buffer(buffer: &mut [u8]) -> Result<usize> {
    // Get raw pointer to buffer data
    let ptr = buffer.as_mut_ptr();
    let len = buffer.len();
    
    // Async boundary - JavaScript can run here!
    some_async_io_operation().await;
    
    // BUG: If JavaScript resized or detached the ArrayBuffer during await,
    // ptr now points to freed/invalid memory
    unsafe {
        // This write goes to potentially freed memory
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, len);  // UAF!
    }
    
    Ok(len)
}

// FIXED: Re-validate buffer after async boundary
async fn read_into_buffer(buffer: &mut TypedArray) -> Result<usize> {
    some_async_io_operation().await;
    
    // Re-acquire the buffer reference after await
    // This will fail if buffer was detached
    let slice = buffer.as_mut_slice()?;  // Returns error if detached
    
    slice.copy_from_slice(&data);
    Ok(slice.len())
}
```
What checker can check this?

### Integer Overflow

| CVE | Crate | Vulnerability Type |
|-----|-------|-------------------|
| **CVE-2025-48756** | scsir | Integer overflow for hardware bit fields |
| **CVE-2024-58263** | cosmwasm-std | Integer overflows in contract calculations |
| **CVE-2023-53156** | transpose | Integer overflow via input dimensions |
| **CVE-2023-22895** | bzip2 | Integer overflow in mem.rs |

#### Code Example: Transpose Integer Overflow (CVE-2023-53156)

```rust
// VULNERABLE: Integer overflow in matrix dimensions
pub fn transpose<T>(input: &[T], width: usize, height: usize) -> Vec<T> 
where T: Clone 
{
    // BUG: width * height can overflow, creating smaller allocation
    let total_size = width * height;  // OVERFLOW on large dimensions!
    let mut output = Vec::with_capacity(total_size);
    
    // Actual data access uses width/height directly
    for y in 0..height {
        for x in 0..width {
            let src_idx = y * width + x;  // Accesses beyond allocation!
            let dst_idx = x * height + y;
            // ...
        }
    }
    output
}

// Example trigger:
let width: usize = (1 << 32) + 1;  // On 64-bit: 4294967297
let height: usize = (1 << 32);     // On 64-bit: 4294967296
// width * height overflows to a small number
// But loop iterates width * height times, causing OOB access

// FIXED: Use checked arithmetic
pub fn transpose<T>(input: &[T], width: usize, height: usize) -> Result<Vec<T>, Error>
where T: Clone
{
    let total_size = width.checked_mul(height)
        .ok_or(Error::Overflow)?;
    
    if input.len() != total_size {
        return Err(Error::DimensionMismatch);
    }
    
    let mut output = Vec::with_capacity(total_size);
    // ... safe to proceed
    Ok(output)
}
```

### Memory Allocation / Resource Exhaustion

| CVE | Crate | Vulnerability Type |
|-----|-------|-------------------|
| **CVE-2025-48755** | spiral-rs | Allocation for ZST (zero-sized type) |
| **CVE-2025-47737** | trailer | Mishandled zero-size allocation |
| **CVE-2024-43410** | Russh | Untrusted memory allocation for OOM |
| **CVE-2024-32984** | Yamux | Unbounded vector for pending frames |
| **CVE-2024-1765** | Cloudflare Quiche | Unlimited resource allocation |
| **CVE-2024-1410** | Cloudflare quiche | Unbounded storage for connection ID |
| **CVE-2023-39410** | Apache Avro | Out of memory from untrusted data |

#### Code Example: Zero-Sized Type Allocation (CVE-2025-48755)

```rust
// VULNERABLE: Incorrect handling of zero-sized types
pub struct Matrix<T> {
    data: *mut T,
    rows: usize,
    cols: usize,
}

impl<T> Matrix<T> {
    pub fn new(rows: usize, cols: usize) -> Self {
        let size = rows * cols;
        
        // BUG: For ZST (size_of::<T>() == 0), allocation returns dangling pointer
        // but code treats it as valid
        let data = if size == 0 {
            std::ptr::NonNull::dangling().as_ptr()
        } else {
            let layout = Layout::array::<T>(size).unwrap();
            unsafe { alloc(layout) as *mut T }
        };
        
        // For ZST, any offset calculation is problematic
        Matrix { data, rows, cols }
    }
    
    pub fn get(&self, row: usize, col: usize) -> &T {
        let idx = row * self.cols + col;
        // BUG: For ZST, this pointer arithmetic is undefined behavior
        unsafe { &*self.data.add(idx) }
    }
}

// FIXED: Handle ZST specially
impl<T> Matrix<T> {
    pub fn get(&self, row: usize, col: usize) -> &T {
        assert!(row < self.rows && col < self.cols);
        
        if std::mem::size_of::<T>() == 0 {
            // For ZST, all instances are identical; return reference to static
            unsafe { &*NonNull::dangling().as_ptr() }
        } else {
            let idx = row * self.cols + col;
            unsafe { &*self.data.add(idx) }
        }
    }
}
```

#### Code Example: Unbounded Allocation from Untrusted Input (CVE-2024-32984)

```rust
// VULNERABLE: Yamux protocol - unbounded vector from network input
struct Connection {
    pending_frames: Vec<Frame>,
}

impl Connection {
    fn handle_frame(&mut self, frame: Frame) -> Result<()> {
        // BUG: Attacker can send unlimited frames without flow control
        // Each frame is stored in memory
        self.pending_frames.push(frame);  // Unbounded growth!
        Ok(())
    }
}

// Attack: Send millions of frames without reading responses
// Server runs out of memory

// FIXED: Limit pending frames
const MAX_PENDING_FRAMES: usize = 1024;

impl Connection {
    fn handle_frame(&mut self, frame: Frame) -> Result<()> {
        if self.pending_frames.len() >= MAX_PENDING_FRAMES {
            return Err(Error::TooManyPendingFrames);
        }
        self.pending_frames.push(frame);
        Ok(())
    }
}
```

### Stack Consumption

| CVE | Crate | Vulnerability Type |
|-----|-------|-------------------|
| **CVE-2024-58264** | serde-json-wasm | Stack consumption via nested JSON |
| **CVE-2024-44073** | rust-miniscript | Stack consumption - not tracking tree depth |

#### Code Example: Stack Consumption via Nested Input (CVE-2024-58264)

```rust
// VULNERABLE: Recursive parsing without depth limit
fn parse_value(input: &str) -> Result<Value> {
    match input.chars().next() {
        Some('[') => {
            // BUG: Recursive call for each nested array
            // [[[[[[...]]]]]] causes stack overflow
            let inner = &input[1..input.len()-1];
            let elements: Vec<Value> = inner
                .split(',')
                .map(|s| parse_value(s.trim()))  // Recursive!
                .collect::<Result<Vec<_>>>()?;
            Ok(Value::Array(elements))
        }
        Some('{') => {
            // Similarly recursive for objects
            parse_object(input)  // Recursive!
        }
        _ => parse_primitive(input),
    }
}

// Attack: Send deeply nested JSON
// "[[[[[[[[[[[[...10000 levels...]]]]]]]]]]]"
// Each level adds a stack frame, eventually causing stack overflow

// FIXED: Track and limit recursion depth
fn parse_value_with_depth(input: &str, depth: usize) -> Result<Value> {
    const MAX_DEPTH: usize = 128;
    
    if depth > MAX_DEPTH {
        return Err(Error::NestingTooDeep);
    }
    
    match input.chars().next() {
        Some('[') => {
            let inner = &input[1..input.len()-1];
            let elements: Vec<Value> = inner
                .split(',')
                .map(|s| parse_value_with_depth(s.trim(), depth + 1))  // Track depth
                .collect::<Result<Vec<_>>>()?;
            Ok(Value::Array(elements))
        }
        // ...
    }
}
```

### Information Exposure / Cryptographic Issues

| CVE | Crate | Vulnerability Type |
|-----|-------|-------------------|
| **CVE-2025-27498** | aes-gcm | Decrypted ciphertext exposed despite tag failure |
| **CVE-2023-42811** | aes-gcm | Decrypted ciphertext exposed on incorrect tag |
| **CVE-2024-34063** | vodozemac | Degraded secret zeroization |

#### Code Example: AES-GCM Tag Verification Bypass (CVE-2023-42811)

```rust
// VULNERABLE: Decrypted plaintext written to output before tag verification
pub fn decrypt_in_place(
    &self,
    nonce: &Nonce,
    associated_data: &[u8],
    buffer: &mut [u8],  // Contains ciphertext, will receive plaintext
) -> Result<(), Error> {
    // Step 1: Decrypt ciphertext to plaintext (in place)
    self.cipher.decrypt_blocks(buffer);  // buffer now contains plaintext!
    
    // Step 2: Verify authentication tag
    let expected_tag = self.compute_tag(nonce, associated_data, buffer);
    let actual_tag = &buffer[buffer.len() - TAG_SIZE..];
    
    if expected_tag != actual_tag {
        // BUG: Plaintext is already in buffer even though tag failed!
        // Attacker can observe timing/cache side channels
        // Or if buffer is shared memory, plaintext is exposed
        return Err(Error::AuthenticationFailed);
    }
    
    Ok(())
}

// FIXED: Don't expose plaintext until tag is verified
pub fn decrypt_in_place(
    &self,
    nonce: &Nonce,
    associated_data: &[u8],
    buffer: &mut [u8],
) -> Result<(), Error> {
    // Verify tag FIRST using ciphertext
    let expected_tag = self.compute_tag_from_ciphertext(nonce, associated_data, buffer);
    let actual_tag = &buffer[buffer.len() - TAG_SIZE..];
    
    if expected_tag.ct_eq(actual_tag).unwrap_u8() != 1 {
        // Return error WITHOUT decrypting - buffer still contains ciphertext
        return Err(Error::AuthenticationFailed);
    }
    
    // Only decrypt AFTER tag verification succeeds
    self.cipher.decrypt_blocks(buffer);
    Ok(())
}
```

#### Code Example: Secret Zeroization Failure (CVE-2024-34063)

```rust
// VULNERABLE: Compiler might optimize away zeroization
impl Drop for SecretKey {
    fn drop(&mut self) {
        // BUG: Compiler sees this write is never read
        // and may optimize it away entirely
        for byte in self.key.iter_mut() {
            *byte = 0;
        }
        // Key material may remain in memory after drop!
    }
}

// Also vulnerable: Using ptr::write_volatile in a loop
impl Drop for SecretKey {
    fn drop(&mut self) {
        for byte in self.key.iter_mut() {
            // BUG: While individual writes are volatile,
            // compiler might still optimize the loop
            unsafe { std::ptr::write_volatile(byte, 0); }
        }
    }
}

// FIXED: Use proper zeroization library
use zeroize::Zeroize;

struct SecretKey {
    key: zeroize::Zeroizing<[u8; 32]>,  // Automatically zeroized on drop
}

// Or manually with compiler fence:
impl Drop for SecretKey {
    fn drop(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.key.as_mut_ptr(), 0, self.key.len());
            // Compiler fence prevents reordering/elimination
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        }
    }
}
```

### Type Safety / Invalid Values

| CVE | Crate | Vulnerability Type |
|-----|-------|-------------------|
| **CVE-2024-58253** | obfstr | Invalid UTF-8 conversion producing invalid value |

---

## Category 3: System Call Wrappers / Kernel

These involve Rust code interacting with the Linux kernel.

| CVE | Component | Description |
|-----|-----------|-------------|
| **CVE-2025-40040** | Linux kernel (mm/ksm) | Kernel-level memory issue with Rust interaction |
| **CVE-2025-38033** | Linux kernel (x86) | CFI/FineIBT issues with Rust `core::fmt::write()` |

---

## Key Findings

### 1. Most Memory Safety Bugs Are in Pure Rust Unsafe Code (73%)

The majority of memory safety vulnerabilities are **NOT** from C FFI bindings, but from:

- Incorrect synchronization in concurrent data structures (crossbeam-channel, Tokio, Mio)
- Iterator/lifetime issues in pure Rust code
- Integer overflow handling
- Incorrect bounds checking in parsers (phonenumber, sequoia-openpgp)

### 2. C FFI Wrappers Account for 23%

The rust-ffmpeg crate alone accounts for 6 of the 12 C FFI vulnerabilities. Common patterns:

- Not checking for NULL return values from C functions
- Assuming C functions always succeed
- Iterator invalidation semantics not matching between C and Rust

### 3. Wasmtime: Complex Pure Rust Unsafe

Wasmtime represents a special case - it's written in pure Rust but has complex unsafe code for WebAssembly runtime implementation. The vulnerabilities involve LLVM-level undefined behavior from Rust code that takes `&self` but modifies data, which the compiler assumes won't happen due to `noalias readonly` semantics.

### 4. Concurrency Bugs Dominate Pure Rust Issues

Many pure Rust memory safety issues stem from:

- Race conditions in `Drop` implementations
- Missing synchronization in lock implementations
- Incorrect `Send`/`Sync` bounds

---

## Case Study: crossbeam-channel Double-Free (CVE-2025-4574)

This is a particularly interesting case because crossbeam-channel is a widely-used, well-audited pure Rust crate.

### The Bug

The internal `Channel` type's `Drop` method has a race condition which could, in some circumstances, lead to a double-free that could result in memory corruption.

### Timeline

- **February 7, 2024**: crossbeam-channel updated from 0.5.8 to 0.5.14
- **February 26, 2024**: CI runs began to intermittently fail with memory corruption errors
- **April 9, 2024**: Race condition finally discovered after ~40 days of investigation
- **May 2025**: CVE-2025-4574 published

### Root Cause

Under certain conditions, the unbounded implementation of crossbeam channels could end up with a double-free. The bug was introduced in February 2024 when a PR that fixed a memory leak changed only one of the loads to a swap operation, which introduced the possibility for a dangling pointer.

### Affected Versions

- crossbeam-channel: 0.5.12 through 0.5.14 (fixed in 0.5.15)
- Rust std channels (based on crossbeam): Also affected

### Lessons Learned

1. Even well-audited concurrent code can have subtle bugs
2. Memory corruption bugs in concurrent code are extremely difficult to diagnose
3. The bug remained undetected for over a year despite being in critical infrastructure

---

## Recommendations

### For Crate Authors

1. **FFI Wrappers**: Always check return values from C functions, especially for NULL
2. **Concurrent Code**: Use tools like `loom` for testing concurrent data structures
3. **Unsafe Code**: Minimize unsafe blocks and document safety invariants
4. **Bounds Checking**: Always validate indices before array access in unsafe code

### For Crate Users

1. Keep dependencies updated, especially security-critical crates
2. Use `cargo audit` to check for known vulnerabilities
3. Consider using memory-safe alternatives when available
4. Monitor security advisories for critical dependencies

### For the Rust Ecosystem

1. Continue investing in tools like Miri and sanitizers
2. Improve documentation around common unsafe pitfalls
3. Consider formal verification for critical infrastructure crates

---

## References

- [RustSec Advisory Database](https://rustsec.org/advisories/)
- [CVE Database](https://cve.org/)
- [rust-cve GitHub Repository](https://github.com/Qwaz/rust-cve)
- [Materialize Blog: Diagnosing a Double-Free Concurrency Bug](https://materialize.com/blog/rust-concurrency-bug-unbounded-channels/)
- [rust-ffmpeg Security Issues](https://github.com/meh/rust-ffmpeg/issues/192)

---

*Document generated: November 2025*
