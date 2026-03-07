use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::{io, usize};
use tun_tap::Iface;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
    ip: Ipv4Header,
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
        // &mut self,
        iface: &mut Iface,
        ip_header: &Ipv4HeaderSlice<'a>,
        tcp_header: &TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];

        if !tcp_header.syn() {
            return Ok(None); // only accept SYN packets for new connections
        }

        let iss = 0; // initial sequence number (should be random in real TCP)
        let mut connection = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss: iss,     // Our starting seq = 0
                una: iss,     // Nothing acknowledged yet
                nxt: iss + 1, // +1 because we're about to send a SYN (which consumes one)
                wnd: 10,
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
        };

        // Here we build the SYN-ACK response:
        // need to start establishing a connection
        let mut syn_ack = TcpHeader::new(
            tcp_header.destination_port(), // From OUR port
            tcp_header.source_port(),      // To THEIR port
            connection.send.iss,           // Our sequence number
            connection.send.wnd,           // Our window size
        );

        syn_ack.acknowledgment_number = connection.recv.nxt; // "I got up to your byte X"
        syn_ack.syn = true;
        syn_ack.ack = true;
        connection.ip.set_payload_len(syn_ack.header_len() + 0);

        // kernel does this for us so we dont need it
        // syn_ack.checksum = syn_ack
        //     .calc_checksum_ipv4(&ip, &[])
        //     .expect("failed to compute checksum");

        // write out the headers
        let unwritten = {
            let mut unwritten = &mut buf[..];
            connection.ip.write(&mut unwritten)?;
            syn_ack.write(&mut unwritten)?;
            unwritten.len()
        };

        iface.send(&buf[..unwritten])?;
        Ok(Some(connection))
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
        //
        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        // but remember wrapping
        //
        let ackn = tcp_header.acknowledgment_number();
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            return Ok(());
        }

        // valid segment check
        // RCV.NXT =< SEG.ACK =< SND.NXT
        // but remember wrapping

        let seqn = tcp_header.sequence_number();
        if !is_between_wrapped(
            self.recv.nxt.wrapping_sub(1),
            seqn,
            self.recv.nxt.wrapping_add(self.recv.wnd as u32),
        ) {
            return Ok(());
        }

        if self.send.una < ackn {
            // check is violated if and only if n is between u and a
            if self.send.nxt >= self.send.una && self.send.nxt < ackn {
                return Ok(());
            }
        } else {
            // check is okay if and only if n is between u and a
            if self.send.nxt >= ackn && self.send.nxt < self.send.una {
            } else {
                return Ok(());
            }
        }

        // if !(self.send.una < tcp_header.acknowledgment_number()
        //     && tcp_header.acknowledgment_number() <= self.send.nxt)
        // {
        //     return Ok(());
        // }

        //
        // valid segment check
        //
        match self.state {
            State::SynRcvd => {
                // expect to get an ACK for our SYN
                unimplemented!()
            }
            State::Estab => {
                unimplemented!()
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
