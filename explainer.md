# TCP from Scratch in Rust — Code Walkthrough

A breakdown of the full codebase for this from-scratch TCP implementation using a TUN device.

---

## The Big Picture

```
My App
   ↕
OS TCP Stack  ← We're REPLACING this
   ↕
TUN Device (tun0) ← Raw IP packets flow here
   ↕
Network
```

A **TUN device** is a virtual network interface. Instead of the kernel handling TCP, raw packets come straight to your program. We parse and respond to them yourself — no OS TCP stack involved.

---

## `main.rs` — The Packet Loop

```rust
let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
```

This `HashMap` tracks **all active TCP connections**. Each connection is identified by a `Quad`:

```rust
struct Quad {
    src: (Ipv4Addr, u16),  // source IP + port
    dst: (Ipv4Addr, u16),  // destination IP + port
}
```

Example quad: `(192.168.1.5:54321) → (10.0.0.1:80)`. That 4-tuple uniquely identifies one TCP connection.

**Every iteration of the loop does this:**

```
Receive raw bytes
  → Parse IPv4 header
    → Is it TCP? (protocol 0x06) → skip if not
      → Parse TCP header
        → Build Quad from src/dst IP+port
          → Known connection? → call on_packet()
          → New connection?   → call accept()
```

---

## The TCP State Machine

TCP connections move through states. The ones implemented here:

```
CLOSED
  ↓
LISTEN         ← Waiting for someone to connect
  ↓  (receive SYN)
SYN_RCVD       ← Got their SYN, sent our SYN-ACK, waiting for their ACK
  ↓  (receive ACK)
ESTABLISHED    ← Data can flow both ways
  ↓
  ... (closing states — not yet implemented)
```

```rust
pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}
```

---

## Sequence Numbers — The Core of TCP

TCP needs to:
1. Know which bytes were received
2. Know which bytes were acknowledged
3. Handle out-of-order or lost packets

**Every byte** sent over TCP has a unique sequence number. The sequence spaces track where things stand.

---

### `SendSequenceSpace` — Tracking What *You* Send

```
         1         2          3          4
     ----------|----------|----------|----------
            SND.UNA    SND.NXT    SND.UNA+SND.WND

  1 - acknowledged (done, forget them)
  2 - sent but not yet acknowledged (in-flight)
  3 - allowed to send (within window)
  4 - not yet allowed to send
```

| Field | Full Name | Meaning |
|-------|-----------|---------|
| `iss` | Initial Send Sequence | The random number you started with |
| `una` | Unacknowledged | Oldest byte they haven't confirmed yet |
| `nxt` | Next | The next byte you will send |
| `wnd` | Window | How many bytes ahead you're allowed to send |
| `up`  | Urgent Pointer | Urgent data flag (unused here) |
| `wl1` | Window Update Seq | Sequence number of last window update |
| `wl2` | Window Update Ack | Ack number of last window update |

**Concrete example:**

```
You sent bytes: 100, 101, 102, 103, 104, 105
They ACK'd up to: 102

iss = 100   ← where you started
una = 102   ← they haven't confirmed 102 yet
nxt = 106   ← next byte you'll send is 106

Bytes 102–105 are "in-flight" (sent, not yet ack'd)
```

---

### `ReceiveSequenceSpace` — Tracking What *They* Send

```
         1          2          3
     ----------|----------|----------
             RCV.NXT    RCV.NXT+RCV.WND

  1 - already acknowledged
  2 - allowed to receive (within window)
  3 - not yet allowed
```

| Field | Full Name | Meaning |
|-------|-----------|---------|
| `irs` | Initial Receive Sequence | Their starting sequence number |
| `nxt` | Next Expected | The next byte you expect from them |
| `wnd` | Window | How much buffer space you have available |
| `up`  | Urgent Pointer | Urgent data flag (unused here) |

---

## `accept()` — The SYN Handshake (Step 2 of 3)

TCP connections start with a **3-way handshake**:

```
Client                         Server (you)
  |                                |
  |-------- SYN ------------------>|  "I want to connect, my seq starts at X"
  |                                |
  |<------- SYN-ACK ---------------|  "OK, my seq starts at Y, I confirm X"  ← accept()
  |                                |
  |-------- ACK ------------------>|  "Got it, we're connected"
```

`accept()` is called when a `Quad` is **not** found in the HashMap — it's a brand new connection attempt.

### Step-by-step

**1. Ignore anything that isn't a SYN:**
```rust
if !tcp_header.syn() {
    return Ok(None);
}
```

**2. Set up the Receive Sequence Space using their numbers:**
```rust
recv: ReceiveSequenceSpace {
    irs: tcp_header.sequence_number(),      // their ISS
    nxt: tcp_header.sequence_number() + 1,  // +1 because SYN consumes one seq number
    wnd: tcp_header.window_size(),
    ...
}
```

> The SYN flag **consumes one sequence number** even though it carries no data payload. Same goes for FIN later.

**3. Set up Send Sequence Space with your own numbers:**
```rust
send: SendSequenceSpace {
    iss: iss,      // your ISS (0 here, should be random in real TCP)
    una: iss,      // nothing acknowledged yet
    nxt: iss + 1,  // +1 because SYN we're about to send also consumes one
    wnd: 10,
    ...
}
```

**4. Build and send the SYN-ACK:**
```rust
syn_ack.acknowledgment_number = connection.recv.nxt; // "I received up to your byte X"
syn_ack.syn = true;  // we're also syncing our seq number
syn_ack.ack = true;  // we're acknowledging their SYN
```

**5. Write IP + TCP headers into the buffer and send:**
```rust
connection.ip.write(&mut unwritten)?;
syn_ack.write(&mut unwritten)?;
iface.send(&buf[..unwritten])?;
```

The connection is then inserted into the `HashMap` and state is `SynRcvd`.

---

## `on_packet()` — Handling Packets on Existing Connections

Called when the `Quad` **is** found in the HashMap — a known connection.

### ACK Validation (RFC 793 §3.3)

Before doing anything, you must verify the ACK number in the incoming packet is valid.

**The rule:**
```
SND.UNA < SEG.ACK <= SND.NXT
```

In plain English: *"They must be acknowledging something we actually sent, but haven't fully confirmed yet."*

```
          ← valid ACK range →
|--done--|--in-flight--|--not-sent--|
       SND.UNA       SND.NXT
```

**The wrapping problem:** Sequence numbers are `u32`. They wrap around from `4,294,967,295` back to `0`. So you can't use plain `<` / `>` — you have to account for wraparound:

```rust
let ackn = tcp_header.acknowledgment_number();

if self.send.una < ackn {
    // Normal (non-wrapped) case
    // INVALID if nxt falls between una and ackn
    // (means they're acking bytes we never sent)
    if self.send.nxt >= self.send.una && self.send.nxt < ackn {
        return Ok(()); // invalid — ignore packet
    }
} else {
    // Wrapped case: una is large, ackn has wrapped to a small number
    // VALID only if nxt is also in the wrapped region
    if self.send.nxt >= ackn && self.send.nxt < self.send.una {
        // valid
    } else {
        return Ok(()); // invalid — ignore packet
    }
}
```

### State Dispatch

After validation, behaviour depends on current state:

```rust
match self.state {
    State::SynRcvd => {
        // Expecting the final ACK of the handshake
        // → transition to Estab
        unimplemented!()
    }
    State::Estab => {
        // Handle data, FIN, window updates, etc.
        unimplemented!()
    }
}
```

---

## Full Flow Summary

```
main loop receives raw bytes
         │
         ▼
    Parse IP header ──── not IPv4? → skip
         │
         ▼
    Parse TCP header ─── not TCP (0x06)? → skip
         │
         ▼
    Build Quad { src: (ip, port), dst: (ip, port) }
         │
         ├── Vacant (new) ──→ tcp::Connection::accept()
         │                        • Must be a SYN packet
         │                        • Init SendSequenceSpace (your seq numbers)
         │                        • Init ReceiveSequenceSpace (their seq numbers)
         │                        • Send SYN-ACK
         │                        • Insert into HashMap, state = SynRcvd
         │
         └── Occupied (known) → tcp::Connection::on_packet()
                                    • Validate ACK number (with wraparound)
                                    • Dispatch on state:
                                        SynRcvd → expect ACK → move to Estab
                                        Estab   → handle data/FIN/RST
```

---

## What's Not Implemented Yet

The `unimplemented!()` macros mark the next steps:

| Location | What needs doing |
|----------|-----------------|
| `SynRcvd` branch in `on_packet` | Receive the client's final ACK → update `send.una` → transition state to `Estab` |
| `Estab` branch in `on_packet` | Handle incoming data, send ACKs, buffer writes, handle FIN for teardown |
| Sequence number validation | Also need to validate `SEG.SEQ` (not just `SEG.ACK`) against `recv.nxt` and `recv.wnd` |
| `iss` randomisation | Should be a random number, not `0`, to prevent TCP sequence prediction attacks |

---

## Key Terms Cheat Sheet

| Term | Meaning |
|------|---------|
| `SND.UNA` | Oldest unacknowledged byte you sent |
| `SND.NXT` | Next byte you will send |
| `SND.WND` | How many bytes ahead you can send |
| `RCV.NXT` | Next byte you expect to receive |
| `RCV.WND` | How much buffer space you're advertising |
| `ISS` | Your initial sequence number |
| `IRS` | Their initial sequence number |
| `SEG.SEQ` | Sequence number of an incoming segment |
| `SEG.ACK` | Acknowledgement number of an incoming segment |
| SYN | Synchronise — opens a connection, consumes one seq number |
| ACK | Acknowledge — confirms receipt of bytes up to this number |
| FIN | Finish — closes a connection, consumes one seq number |
