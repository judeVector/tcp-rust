use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::io;
use tun_tap::Iface;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    // Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
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
    pub fn accept<'a>(
        // &mut self,
        iface: &mut Iface,
        ip_header: &Ipv4HeaderSlice<'a>,
        tcp_header: &TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];

        if !tcp_header.syn() {
            // only expect SYN packet
            return Ok(None);
        }

        let iss = 0;
        let connection = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss: iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                up: false,
                wll: 0,
                wl2: 0,
            },
            recv: ReceiveSequenceSpace {
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),
                up: false,
                irs: tcp_header.sequence_number(),
            },
        };

        // need to start establishing a connection
        let mut syn_ack = TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            connection.send.iss,
            connection.send.wnd,
        );

        syn_ack.acknowledgment_number = connection.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;

        let ip = Ipv4Header::new(
            syn_ack.header_len_u16(),
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
        .unwrap();

        // kernel does this for us so we dont need it
        // syn_ack.checksum = syn_ack
        //     .calc_checksum_ipv4(&ip, &[])
        //     .expect("failed to compute checksum");

        // write out the headers
        let unwritten = {
            let mut unwritten = &mut buf[..];
            ip.write(&mut unwritten)?;
            syn_ack.write(&mut unwritten)?;
            unwritten.len()
        };

        iface.send(&buf[..unwritten])?;
        Ok(Some(connection))
    }

    pub fn on_packet<'a>(
        &mut self, // mutable reference to the instance
        iface: &mut Iface,
        ip_header: &Ipv4HeaderSlice<'a>,
        tcp_header: &TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // Implement the logic for handling the packet here.
        Ok(())
    }
}
