use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use tun_tap::{Iface, Mode};

mod tcp;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut iface =
        Iface::without_packet_info("tun0", Mode::Tun).expect("failed to create TUN device");
    let mut buf = vec![0u8; 1504];
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();

    loop {
        let nbytes = iface.recv(&mut buf)?;
        // let _eth_flags = u16::from_be_bytes([buf[1], buf[2]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        // if eth_proto != 0x0800 {
        //     // not ipv4
        //     continue;
        // }

        match Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dest = ip_header.destination_addr();

                if ip_header.protocol() != IpNumber(0x06) {
                    // not tcp
                    continue;
                }

                match TcpHeaderSlice::from_slice(&buf[ip_header.slice().len()..nbytes]) {
                    Ok(tcp_header) => {
                        use std::collections::hash_map::Entry;

                        let datai = ip_header.slice().len() + tcp_header.slice().len();

                        match connections.entry(Quad {
                            src: (src, tcp_header.source_port()),
                            dst: (dest, tcp_header.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => c.get_mut().on_packet(
                                &mut iface,
                                &ip_header,
                                &tcp_header,
                                &buf[datai..nbytes],
                            )?,
                            Entry::Vacant(e) => {
                                if let Some(c) = tcp::Connection::accept(
                                    // &mut self,
                                    &mut iface,
                                    &ip_header,
                                    &tcp_header,
                                    &buf[datai..nbytes],
                                )? {
                                    e.insert(c);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet: {:?}", e);
                    }
                }
            }
            Err(_e) => {
                // eprintln!("ignoring weird packet: {:?}", e);
            }
        }
    }
}
