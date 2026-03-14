use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::io;
use tun_tap::Iface;

pub enum State {
    // Closed,
    // Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
}
impl State {
    fn is_non_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 => true,
            // State::Closed => false,
            // State::Listen => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
    ip: Ipv4Header,
    tcp: TcpHeader,
}

/// State of the Send Sequence Space (RFC 793 S3.2)

/// ```
///         1         2          3          4
///     ----------|----------|----------|----------
///            SND.UNA    SND.NXT    SND.UNA
///                                 +SND.WND

/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
struct SendSequenceSpace {
    /// initial send sequence number
    iss: u32,
    /// send unacknowledge
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segmet sequence number used for last window update
    wll: usize,
    /// segment acknowledgement number used for last window
    wl2: usize,
}

/// State of the Receive Sequence Space
/// ```
///         1          2          3
///     ----------|----------|----------
///             RCV.NXT    RCV.NXT
///                     +RCV.WND

/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
struct ReceiveSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

// impl Default for Connection {
//     fn default() -> Self {
//         Connection {
//             state: State::Listen,
//         }
//     }
// }

impl Connection {
    /// ## `accept()` — The SYN Handshake

    /// TCP connections start with a **3-way handshake**:
    /// ```
    /// Client                    Server (We)
    ///   |                           |
    ///   |-------- SYN ------------->|   "I want to connect, my seq starts at X"
    ///   |                           |
    ///   |<------- SYN-ACK ----------|   "OK, my seq starts at Y, I got your X"
    ///   |                           |
    ///   |-------- ACK ------------->|   "Got it, we're connected"
    pub fn accept<'a>(
        iface: &mut Iface,
        ip_header: &Ipv4HeaderSlice<'a>,
        tcp_header: &TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        if !tcp_header.syn() {
            return Ok(None); // only accept SYN packets for new connections
        }

        let iss = 0; // initial sequence number (should be random in real TCP)
        let wnd = 10;
        let mut connection = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss: iss, // Our starting seq = 0
                una: iss, // Nothing acknowledged yet
                nxt: iss, // We haven't written the syn byte yet
                wnd: wnd,
                up: false,
                wll: 0,
                wl2: 0,
            },
            recv: ReceiveSequenceSpace {
                nxt: tcp_header.sequence_number() + 1, // +1 because SYN consumes one seq number
                wnd: tcp_header.window_size(),
                up: false,
                irs: tcp_header.sequence_number(), // Their starting seq number
            },
            ip: Ipv4Header::new(
                0,
                64,
                IpNumber::TCP,
                [
                    ip_header.destination()[0],
                    ip_header.destination()[1],
                    ip_header.destination()[2],
                    ip_header.destination()[3],
                ],
                [
                    ip_header.source()[0],
                    ip_header.source()[1],
                    ip_header.source()[2],
                    ip_header.source()[3],
                ],
            )
            .unwrap(),
            // Here we build the SYN-ACK response:
            tcp: TcpHeader::new(
                tcp_header.destination_port(), // From OUR port
                tcp_header.source_port(),      // To THEIR port
                iss,                           // Our sequence number
                wnd,                           // Our window size
            ),
        };

        // syn_ack.acknowledgment_number = connection.recv.nxt; // "I got up to your byte X"
        connection.tcp.syn = true;
        connection.tcp.ack = true;
        connection.write(iface, &[])?;

        Ok(Some(connection))
    }

    fn write(&mut self, iface: &mut Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];

        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt; // "I got up to your byte X"

        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() + self.ip.header_len() + payload.len(),
        );
        self.ip.set_payload_len(size);

        // kernel does this for us so we dont need it
        // self.tcp.checksum = self.tcp
        //     .calc_checksum_ipv4(&self.ip, &[])
        //     .expect("failed to compute checksum");

        // write out the headers
        use std::io::Write;

        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten)?;
        self.tcp.write(&mut unwritten)?;
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();
        self.send.nxt.wrapping_add(payload_bytes as u32);

        if self.tcp.syn {
            self.send.nxt += self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }

        if self.tcp.fin {
            self.send.nxt += self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        iface.send(&buf[..buf.len() - unwritten])?;

        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut Iface) -> io::Result<()> {
        self.tcp.rst = true;
        // TODO: fix sequence number
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // The connection remains in the same state.
        //
        // TODO: handle synchronized RST
        // If the connection is in a synchronized state (ESTABLISHED,
        // FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        // any unacceptable segment (out of window sequence number or
        // unacceptible acknowledgment number) must elicit only an empty
        // acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received, and the connection remains in the same state.
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;

        Ok(())
    }

    /// ## `on_packet()` — The ACK Validation
    /// This is called for **packets on an existing connection**.
    /// The first thing it does is validate the ACK number.
    ///
    /// **The rule from RFC 793:**
    /// > `SND.UNA < SEG.ACK <= SND.NXT`
    /// ```
    ///          valid ACK range
    ///               ↓↓↓↓↓
    /// |--acknowledged--|--in-flight--|--not-sent-yet--|
    ///               SND.UNA       SND.NXT
    pub fn on_packet<'a>(
        &mut self,
        iface: &mut Iface,
        ip_header: &Ipv4HeaderSlice<'a>,
        tcp_header: &TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // first check that sequence numbers are valid (RFC 793 S3.3)

        // valid segment check, okay if it acks at least one byte, which means that at least one
        // of the following is true
        //
        // RCV.NXT =< SEG.SEQN =< RCV.NXT+RCV.WND
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND

        let seqn = tcp_header.sequence_number();
        let mut slen = data.len() as u32;
        if tcp_header.fin() {
            slen += 1;
        };
        if tcp_header.syn() {
            slen + 1;
        }

        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        if slen == 0 {
            // zero-length segment has seperate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                return Ok(());
            }
        }

        // if self.send.una < ackn {
        //     // check is violated if and only if n is between u and a
        //     if self.send.nxt >= self.send.una && self.send.nxt < ackn {
        //         return Ok(());
        //     }
        // } else {
        //     // check is okay if and only if n is between u and a
        //     if self.send.nxt >= ackn && self.send.nxt < self.send.una {
        //     } else {
        //         return Ok(());
        //     }
        // }

        // if !(self.send.una < tcp_header.acknowledgment_number()
        //     && tcp_header.acknowledgment_number() <= self.send.nxt)
        // {
        //     return Ok(());
        // }

        self.recv.nxt = seqn.wrapping_add(slen);
        // TODO: if _not_ acceptable , send ACK
        // <SEQ=SND.NXT><ACK=RCV.NXT>CTL=ACK

        if tcp_header

        //
        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        // but remember wrapping
        //
        let ackn = tcp_header.acknowledgment_number();
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            if !self.state.is_non_synchronized() {
                // according to Reset Generation, we should send a RST

                self.send_rst(iface);
            }
            return Ok(());
        }

        self.send.una = ackn;

        //
        // valid segment check
        //
        match self.state {
            State::SynRcvd => {
                // expect to get an ACK for our SYN
                if !tcp_header.ack() {
                    return Ok(());
                }
                // must have ACKed our SYN, since we detected at least one acked byte, and we have
                // only sent one byte (the SYN)
                self.state = State::Estab;

                // now lets terminate the connection
                self.tcp.fin = true;
                self.write(iface, &[])?;
                self.state = State::FinWait1;
            }
            State::Estab => {
                unimplemented!()
            }
            State::FinWait1 => {
                if !tcp_header.fin() || !data.is_empty() {
                    unimplemented!()
                }

                // must have ACKed our FIN, since we detected at least one acked byte, and we have
                // only sent one byte (the FIN)
                self.state = State::FinWait2
            }
            State::FinWait2 => {
                if !tcp_header.fin() || !data.is_empty() {
                    unimplemented!()
                }

                // must have ACKed our FIN, since we detected at least one acked byte, and we have
                // only sent one byte (the FIN)
                self.tcp.fin = false;
                self.write(iface, &[])?;
                self.state = State::Closing
            }
        }

        Ok(())
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::{Ord, Ordering};

    match start.cmp(&x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            // we have:
            //
            //       0 |-----------------S----------X-------------------------| (wraparound)
            //
            //  X is between S and E (S < X < E) in these cases:
            //
            //       0 |-----------------S----------X------E-------------------| (wraparound)
            //
            //       0 |-----------------E----------S------X-------------------| (wraparound)
            //
            //  but "not" in these cases
            //
            //       0 |-----------------S----------E------X-------------------| (wraparound)
            //
            //       0 |-----------------|----------X------E-------------------| (wraparound)
            //                         ^-S+E
            //       0 |-----------------S----------|------------------------| (wraparound)
            //                                 X+E^
            // or in other words, iff !(S <= E <= X)
            if end >= start && end <= x {
                return false;
            }
        }
        Ordering::Greater => {
            // we have the opposite of above:
            //
            //       0 |-----------------X----------S-------------------------| (wraparound)
            //
            //  X is between S and E (S < X < E) only in these cases:
            //
            //       0 |-----------------X--E---S------------------------------| (wraparound)
            //
            //  but "not" in these cases
            //
            //       0 |-----------------X----------S------E-------------------| (wraparound)
            //
            //       0 |-----------------E----X------S------------------------| (wraparound)
            //
            //       0 |-----------------|----------X------E-------------------| (wraparound)
            //                         ^-X+E
            //       0 |-----------------X----------|------------------------| (wraparound)
            //                                 S+E^
            // or in other words, iff !(S < E < X)
            if end < start && end > x {
            } else {
                return false;
            }
        }
    }
    true
}
