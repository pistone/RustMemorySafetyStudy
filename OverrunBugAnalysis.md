# Rust CVE Buggy Code Analysis

This document analyzes 7 Rust CVEs with vulnerable code examples and simple explanations.

---

## CVE-2023-28448: Versionize FamStructWrapper Out-of-Bounds

**Crate:** `versionize` (for `vmm_sys_util::fam::FamStructWrapper`)  
**Impact:** Out-of-bounds read/write  
**Fixed in:** 0.1.10

### The Bug

The `Versionize::deserialize` implementation for `FamStructWrapper<T>` did not validate that the deserialized header's length field matched the actual number of entries in the flexible array.

### Vulnerable Code Pattern

```rust
// FamStructWrapper stores a header with a "count" field followed by 
// a flexible array of entries. The INVARIANT is:
//   header.len() == actual_entries_allocated

impl<T: Default + FamStruct> Versionize for FamStructWrapper<T> {
    fn deserialize<R: Read>(
        reader: &mut R,
        version_map: &VersionMap,
        app_version: u16,
    ) -> Result<Self, VersionizeError> {
        // Deserialize the header (contains length field)
        let header = T::deserialize(reader, version_map, app_version)?;
        
        // Deserialize the entries array
        let entries: Vec<T::Entry> = Vec::deserialize(reader, version_map, app_version)?;
        
        // BUG: No validation that header.len() == entries.len() !!!
        
        // Create wrapper with potentially mismatched lengths
        let mut wrapper = FamStructWrapper::new(header.len());
        wrapper.set_header(header);
        for entry in entries {
            wrapper.push(entry)?;  // Or direct memory copy
        }
        
        Ok(wrapper)
    }
}
```

### Exploitation Scenario

```rust
// Attacker crafts serialized data where:
// - Header claims: len = 255
// - Actual entries: len = 0

// After deserialization:
let wrapper: FamStructWrapper<MyStruct> = deserialize(malicious_data)?;

// The as_slice() method trusts the header:
impl<T: FamStruct> FamStructWrapper<T> {
    pub fn as_slice(&self) -> &[T::Entry] {
        let count = self.header.len();  // Returns 255 from attacker
        let entries_ptr = self.entries.as_ptr();
        unsafe {
            // Creates slice claiming 255 entries exist
            // but only 0 are actually allocated!
            std::slice::from_raw_parts(entries_ptr, count)
        }
    }
}

// Safe code triggers out-of-bounds read:
for entry in wrapper.as_slice() {  // Reads unallocated memory!
    println!("{:?}", entry);
}
```

### The Fix

```rust
fn deserialize<R: Read>(...) -> Result<Self, VersionizeError> {
    let header = T::deserialize(reader, version_map, app_version)?;
    let entries: Vec<T::Entry> = Vec::deserialize(reader, version_map, app_version)?;
    
    // FIX: Validate lengths match before creating wrapper
    if header.len() != entries.len() {
        return Err(VersionizeError::Deserialize(
            "Header length doesn't match entries length".into()
        ));
    }
    
    // Safe to proceed...
}
```

---

## CVE-2023-41051: vm-memory VolatileMemory Trait Bounds Check

**Crate:** `vm-memory`  
**Impact:** Out-of-bounds memory access in VM physical memory  
**Fixed in:** 0.12.2

### The Bug

The default trait implementations for `VolatileMemory` methods like `get_ref()`, `get_array_ref()`, `aligned_as_ref()` assumed that `get_slice(offset, count)` would always return a slice of exactly `count` bytes. If a custom implementation returned a shorter slice, the unsafe code would access out-of-bounds memory.

### Vulnerable Code Pattern

```rust
pub trait VolatileMemory {
    /// Returns a VolatileSlice of `count` bytes starting at `offset`.
    /// 
    /// NOTE: Documentation says it should return `count` bytes,
    /// but implementations may not follow this!
    fn get_slice(&self, offset: usize, count: usize) 
        -> Result<VolatileSlice<...>>;
    
    /// Gets a reference to type T at offset
    fn get_ref<T: ByteValued>(&self, offset: usize) 
        -> Result<VolatileRef<T, ...>> 
    {
        let slice = self.get_slice(offset, size_of::<T>())?;
        
        // BUG: No check that slice.len() == size_of::<T>()!
        // A buggy get_slice() could return fewer bytes.
        
        unsafe {
            // If slice is shorter than size_of::<T>(), this creates
            // a reference that extends past the actual allocation!
            Ok(VolatileRef::with_bitmap(
                slice.addr,
                slice.bitmap.clone(),
            ))
        }
    }
    
    /// Gets an array reference of N elements of type T
    fn get_array_ref<T: ByteValued>(&self, offset: usize, n: usize) 
        -> Result<VolatileArrayRef<T, ...>> 
    {
        let nbytes = n.checked_mul(size_of::<T>())
            .ok_or(Error::Overflow)?;
        let slice = self.get_slice(offset, nbytes)?;
        
        // BUG: No validation that slice.len() == nbytes!
        
        unsafe {
            Ok(VolatileArrayRef::with_bitmap(
                slice.addr,
                n,  // Claims N elements exist
                slice.bitmap.clone(),
            ))
        }
    }
}
```

### Custom Implementation That Breaks Contract

```rust
struct BuggyMemory {
    data: Vec<u8>,
}

impl VolatileMemory for BuggyMemory {
    fn get_slice(&self, offset: usize, count: usize) 
        -> Result<VolatileSlice<...>> 
    {
        // Buggy: Returns shorter slice if request exceeds bounds
        // instead of returning an error
        let available = self.data.len().saturating_sub(offset);
        let actual_len = count.min(available);  // BUG: Can be < count!
        
        Ok(VolatileSlice::new(
            self.data[offset..].as_ptr(),
            actual_len,  // Might be less than requested!
        ))
    }
}

// Exploitation:
let mem = BuggyMemory { data: vec![0u8; 10] };

// Request a reference to a 100-byte struct at offset 0
// get_slice returns only 10 bytes, but get_ref creates
// a reference claiming 100 bytes exist
let bad_ref: VolatileRef<[u8; 100]> = mem.get_ref(0)?;  

// Accessing this reference reads 90 bytes beyond allocation!
let data = bad_ref.load();  // OUT-OF-BOUNDS READ!
```

### The Fix

```rust
fn get_ref<T: ByteValued>(&self, offset: usize) 
    -> Result<VolatileRef<T, ...>> 
{
    let slice = self.get_slice(offset, size_of::<T>())?;
    
    // FIX: Verify slice is correct length
    assert_eq!(
        slice.len(),
        size_of::<T>(),
        "VolatileMemory::get_slice(offset, count) returned slice of length != count."
    );
    
    unsafe {
        Ok(VolatileRef::with_bitmap(slice.addr, slice.bitmap.clone()))
    }
}
```

---

## CVE-2023-53161: buffered-reader Out-of-Bounds Array Access

**Crate:** `buffered-reader`  
**Impact:** Panic (denial of service)  
**Fixed in:** 1.1.5 / 1.2.0

### The Bug

Attacker-controlled input could result in the use of an out-of-bound array index. Rust's bounds checking detects this and panics, causing a denial of service.

### Vulnerable Code Pattern

```rust
// In buffered-reader, parsing code uses indices from input data
// to access internal arrays without proper validation

impl<R: Read> BufferedReader<R> {
    fn process_block(&mut self, input: &[u8]) -> Result<(), Error> {
        // Input contains an index value
        let index = input[0] as usize;
        
        // BUG: No bounds check before array access!
        // If index >= self.lookup_table.len(), Rust will panic
        let value = self.lookup_table[index];  // PANIC if out of bounds!
        
        // Process value...
        self.output.push(value);
        Ok(())
    }
}
```

### Exploitation

```rust
// Attacker sends data with index = 255
// but lookup_table only has 128 entries

let malicious_input: &[u8] = &[255, /* rest of data */];
let mut reader = BufferedReader::new(source);

// This will panic with "index out of bounds: the len is 128 but the index is 255"
reader.process_block(malicious_input)?;  // PANIC!
```

### The Fix

```rust
fn process_block(&mut self, input: &[u8]) -> Result<(), Error> {
    let index = input[0] as usize;
    
    // FIX: Bounds check with graceful error handling
    let value = self.lookup_table.get(index)
        .ok_or(Error::InvalidIndex(index))?;
    
    self.output.push(*value);
    Ok(())
}
```

---

## CVE-2023-53160: sequoia-openpgp Out-of-Bounds Array Access

**Crate:** `sequoia-openpgp`  
**Impact:** Panic (denial of service)  
**Fixed in:** 1.16.0

### The Bug

Similar to buffered-reader, the OpenPGP parsing code had paths where attacker-controlled indices were used to access arrays without bounds validation, leading to panic.

### Vulnerable Code Pattern

```rust
// In OpenPGP packet parsing, signature type or algorithm IDs
// from untrusted input index into lookup tables

const SIGNATURE_TYPES: [&str; 16] = [
    "Binary", "Text", "Standalone", /* ... only 16 entries */
];

impl Signature {
    fn parse(data: &[u8]) -> Result<Self, Error> {
        let sig_type = data[0];  // Attacker-controlled byte
        
        // BUG: sig_type can be 0-255, but array only has 16 entries!
        let type_name = SIGNATURE_TYPES[sig_type as usize];  // PANIC!
        
        // Continue parsing...
    }
}
```

### Another Vulnerable Pattern

```rust
// Hash algorithm lookup
const HASH_ALGORITHMS: [Option<&str>; 12] = [
    None,                    // 0: Reserved
    Some("MD5"),             // 1
    Some("SHA1"),            // 2
    // ... up to index 11
];

fn get_hash_name(algorithm_id: u8) -> Result<&'static str, Error> {
    // BUG: algorithm_id can be up to 255
    match HASH_ALGORITHMS[algorithm_id as usize] {  // PANIC if >= 12!
        Some(name) => Ok(name),
        None => Err(Error::UnknownAlgorithm),
    }
}
```

### The Fix

```rust
fn get_hash_name(algorithm_id: u8) -> Result<&'static str, Error> {
    // FIX: Use .get() for safe bounds-checked access
    match HASH_ALGORITHMS.get(algorithm_id as usize) {
        Some(Some(name)) => Ok(*name),
        Some(None) => Err(Error::ReservedAlgorithm),
        None => Err(Error::UnknownAlgorithm),  // Out of range
    }
}
```

---

## CVE-2023-42444: phonenumber Panic-Guarded Out-of-Bounds

**Crate:** `phonenumber` (rust-phonenumber)  
**Impact:** Panic (denial of service)  
**Fixed in:** 0.3.3+8.13.9, backported to 0.2.5+8.11.3

### The Bug

The phonenumber parsing code for RFC3966 format had a panic-guarded out-of-bounds access when parsing malformed phone numbers like `.;phone-context=`.

### Vulnerable Code Pattern

```rust
impl PhoneNumber {
    fn parse_rfc3966(input: &str) -> Result<Self, ParseError> {
        // RFC3966 format: tel:+1-201-555-0123;phone-context=example.com
        
        // Find the phone-context parameter
        if let Some(ctx_pos) = input.find(";phone-context=") {
            let number_part = &input[..ctx_pos];
            
            // BUG: Assumes number_part is not empty and has valid structure
            // For input ".;phone-context=", number_part is just "."
            
            // This may index into empty or very short strings:
            let first_char = number_part.chars().next().unwrap();  // OK for "."
            
            // But later parsing assumes certain structure exists:
            if number_part.starts_with('+') {
                // Parse international format
                let country_code_end = number_part[1..].find('-')
                    .unwrap_or(number_part.len() - 1);
                
                // BUG: For ".", this tries to slice beyond bounds
                let country_code = &number_part[1..=country_code_end];  // PANIC!
            }
        }
        
        // ...
    }
}
```

### Exploitation

```rust
use phonenumber::parse;

// Malicious input triggers panic
let result = parse(None, ".;phone-context=");  // PANIC!

// The "." before semicolon is parsed as the number part,
// but the code expects a valid phone number structure
```

### The Fix

```rust
fn parse_rfc3966(input: &str) -> Result<Self, ParseError> {
    if let Some(ctx_pos) = input.find(";phone-context=") {
        let number_part = &input[..ctx_pos];
        
        // FIX: Validate number_part has expected structure
        if number_part.is_empty() {
            return Err(ParseError::InvalidNumber);
        }
        
        if number_part.starts_with('+') {
            // FIX: Use safe bounds checking
            if number_part.len() < 2 {
                return Err(ParseError::InvalidNumber);
            }
            
            let rest = &number_part[1..];
            let country_code_end = rest.find('-').unwrap_or(rest.len());
            if country_code_end == 0 {
                return Err(ParseError::InvalidNumber);
            }
            
            let country_code = &rest[..country_code_end];
            // Safe to proceed...
        }
    }
    // ...
}
```

---

## CVE-2024-39697: phonenumber Assert Panic on Large Numbers

**Crate:** `phonenumber` (rust-phonenumber)  
**Impact:** Panic (denial of service)  
**Fixed in:** 0.3.6

### The Bug

The phonenumber parsing code had a reachable `assert!` that triggered when parsing numbers that could be interpreted as values larger than 2^56.

### Vulnerable Code Pattern

```rust
impl PhoneNumber {
    fn parse_number_part(input: &str) -> Result<u64, ParseError> {
        // Parse the numeric portion of a phone number
        // Phone numbers should be reasonable lengths, but input is untrusted
        
        let digits: String = input.chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        
        // Try to parse as u64
        let number: u64 = digits.parse()
            .map_err(|_| ParseError::InvalidNumber)?;
        
        // BUG: Assert that assumes phone numbers fit in reasonable bounds
        // This was added for internal invariant checking, not input validation
        assert!(number < (1u64 << 56), "Number too large for phone number");
        
        Ok(number)
    }
}
```

### Exploitation

```rust
use phonenumber::parse;

// Malicious input: +dwPAA;phone-context=AA
// "dwPAA" is interpreted as a very large number when parsed
// (possibly through some encoding or parsing quirk)

// Or directly: a string that parses to number >= 2^56
let malicious = "+99999999999999999;phone-context=AA";

// Triggers the assert!, causing panic
let result = parse(None, malicious);  // PANIC: "Number too large for phone number"
```

### The Fix

```rust
fn parse_number_part(input: &str) -> Result<u64, ParseError> {
    let digits: String = input.chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    
    let number: u64 = digits.parse()
        .map_err(|_| ParseError::InvalidNumber)?;
    
    // FIX: Return error instead of panic
    if number >= (1u64 << 56) {
        return Err(ParseError::NumberTooLarge);
    }
    
    Ok(number)
}
```

---

## CVE-2024-51502: loona-hpack Decoder Panic

**Crate:** `loona-hpack`  
**Impact:** Panic (denial of service)  
**Fixed in:** 0.4.3

### The Bug

The HPACK decoder could panic when processing untrusted input. Specifically, the `update_max_dynamic_size` function panicked when the buffer was too short to parse a variable-length integer after encountering a SizeUpdate field. This is the same vulnerability as the original `hpack-rs` issue #11.

### Vulnerable Code Pattern

```rust
impl Decoder {
    pub fn decode(&mut self, buf: &[u8]) -> Result<Vec<Header>, DecoderError> {
        let mut cursor = 0;
        let mut headers = Vec::new();
        
        while cursor < buf.len() {
            let first_byte = buf[cursor];
            
            // Check for dynamic table size update (starts with binary 001)
            if first_byte & 0b11100000 == 0b00100000 {
                // BUG: Assumes there are more bytes to read for the integer
                cursor += 1;
                
                // decode_integer expects bytes after the prefix
                // but buffer might be empty after cursor increment!
                let (new_size, consumed) = self.decode_integer(
                    &buf[cursor..],  // Could be empty slice!
                    5,  // 5-bit prefix
                )?;
                
                self.update_max_dynamic_size(new_size);
                cursor += consumed;
            }
            // ... other cases
        }
        
        Ok(headers)
    }
    
    fn decode_integer(&self, buf: &[u8], prefix_bits: u8) -> Result<(usize, usize), DecoderError> {
        // Variable-length integer decoding per HPACK spec
        if buf.is_empty() {
            // BUG: Some code paths didn't handle empty buffer!
            panic!("Buffer too short");  // Or index out of bounds
        }
        
        let prefix_mask = (1 << prefix_bits) - 1;
        let value = buf[0] & prefix_mask;  // PANIC if buf is empty!
        
        if value < prefix_mask {
            return Ok((value as usize, 1));
        }
        
        // Multi-byte integer: need more bytes
        let mut result = prefix_mask as usize;
        let mut shift = 0;
        
        for (i, &byte) in buf[1..].iter().enumerate() {
            result += ((byte & 0x7F) as usize) << shift;
            if byte & 0x80 == 0 {
                return Ok((result, i + 2));
            }
            shift += 7;
        }
        
        // BUG: If loop completes without finding end, panic or return garbage
        panic!("Incomplete integer");
    }
}
```

### Exploitation

```rust
use loona_hpack::Decoder;

// Malicious HPACK data:
// 0x20 = Size update prefix with value 0 (signals need more bytes)
// No following bytes = buffer too short to parse integer

let malicious_hpack: &[u8] = &[0x20];  // Size update, but no integer data

let mut decoder = Decoder::new();
let result = decoder.decode(malicious_hpack);  // PANIC!
```

### The Fix

```rust
fn decode_integer(&self, buf: &[u8], prefix_bits: u8) -> Result<(usize, usize), DecoderError> {
    // FIX: Handle empty buffer gracefully
    if buf.is_empty() {
        return Err(DecoderError::BufferTooShort);
    }
    
    let prefix_mask = (1 << prefix_bits) - 1;
    let value = buf[0] & prefix_mask;
    
    if value < prefix_mask {
        return Ok((value as usize, 1));
    }
    
    let mut result = prefix_mask as usize;
    let mut shift = 0;
    
    for (i, &byte) in buf[1..].iter().enumerate() {
        result += ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, i + 2));
        }
        shift += 7;
        
        // FIX: Prevent overflow
        if shift > 63 {
            return Err(DecoderError::IntegerOverflow);
        }
    }
    
    // FIX: Return error instead of panic
    Err(DecoderError::IncompleteInteger)
}
```

---

## Summary Table

| CVE | Crate | Root Cause | Impact |
|-----|-------|-----------|--------|
| CVE-2023-28448 | versionize | No validation of header.len vs entries.len in deserialize | OOB read/write |
| CVE-2023-41051 | vm-memory | Trait assumed get_slice returns correct length | OOB memory access |
| CVE-2023-53161 | buffered-reader | Untrusted index used for array access | Panic (DoS) |
| CVE-2023-53160 | sequoia-openpgp | Untrusted index used for array access | Panic (DoS) |
| CVE-2023-42444 | phonenumber | No validation of input structure before indexing | Panic (DoS) |
| CVE-2024-39697 | phonenumber | Reachable assert! on untrusted input | Panic (DoS) |
| CVE-2024-51502 | loona-hpack | Buffer underflow in integer decoding | Panic (DoS) |

## Common Patterns

1. **Trusting untrusted data**: Using values from deserialized/parsed input as array indices without bounds checking.

2. **Implicit contract violations**: Trait default implementations assuming implementors follow documentation, but not enforcing it.

3. **Assert vs Error**: Using `assert!` or `panic!` for conditions that can be triggered by untrusted input instead of returning errors.

4. **Missing input validation**: Not checking that input has expected structure before parsing.

5. **Buffer length assumptions**: Assuming buffers have sufficient data without checking.
