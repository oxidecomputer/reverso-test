use anyhow::{Result, anyhow, bail};
use bootserver::dlpi;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types, echo_request};
use pnet::packet::ipv6::MutableIpv6Packet;
use std::env;
use std::net::Ipv6Addr;
use std::thread;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [-v|--verbose] <interface_name>", args[0]);
        std::process::exit(1);
    }
    let verbose = args[1..args.len() - 1]
        .iter()
        .any(|a| matches!(a.as_str(), "-v" | "--verbose"));
    let interface_name = args.last().unwrap();

    // Find the network interface
    let interfaces = pnet::datalink::interfaces();
    let iface = match interfaces.iter().find(|i| i.name == *interface_name) {
        Some(i) => i,
        None => {
            bail!("Interface '{interface_name}' not found");
        }
    };
    let ipv6 = iface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            std::net::IpAddr::V4(_) => None,
            std::net::IpAddr::V6(ip) => {
                if ip.is_unicast_link_local() {
                    Some(ip)
                } else {
                    None
                }
            }
        })
        .ok_or_else(|| anyhow!("could not get IP address"))?;

    // Link-local addresses in EUI-64 format have the MAC address embedded
    // in segments 4-6 (bytes 8-15): fe80:0000:0000:0000:XXYY:ZZFF:FEWW:VVUU
    // where XX-YY-FF-FE-WW is inserted by the EUI-64 process
    // Original MAC: XX-YY-ZZ-WW-VV-UU
    let segments = ipv6.segments();

    // Extract bytes 8-15 (segments 4-7)
    let byte1 = ((segments[4] >> 8) as u8) ^ 0x02; // Flip the U/L bit
    let byte2 = (segments[4] & 0xFF) as u8;
    let byte3 = (segments[5] >> 8) as u8;
    // segments[5] & 0xFF should be 0xFF
    // segments[6] >> 8 should be 0xFE
    let byte4 = (segments[6] & 0xFF) as u8;
    let byte5 = (segments[7] >> 8) as u8;
    let byte6 = (segments[7] & 0xFF) as u8;

    let mac = dlpi::Address {
        addr: [byte1, byte2, byte3, byte4, byte5, byte6],
    };

    // Send to a multicast address
    let dst_addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x01de, 2);
    if verbose {
        println!("Testing interface: {}", iface.name);
        println!("MAC address: {mac}");
        println!("Source address:      {ipv6}");
        println!("Destination address: {dst_addr}");
    }

    let frame = construct_icmpv6_frame(
        ipv6,
        dst_addr,
        &rand::random(), // payload
        rand::random(),  // identifier
        rand::random(),  // sequence
    )?;

    let (tx, rx) = std::sync::mpsc::channel();
    let interface_name_ = interface_name.to_owned();
    let frame_ = frame.clone();
    let rx_handle = thread::spawn(move || -> Result<bool> {
        let mut iface_recv = dlpi::Dlpi::open(&interface_name_)?;
        iface_recv.bind_ethertype(u32::from(EtherTypes::Ipv6.0))?;
        iface_recv.promisc_on()?;
        let end_time =
            std::time::Instant::now() + std::time::Duration::from_millis(100);
        tx.send(()).unwrap(); // unblock the main thread
        while std::time::Instant::now() < end_time {
            if let Some(packet) = iface_recv.recv(Some(100))? {
                if verbose {
                    println!(
                        "Got packet from {} to {}:",
                        packet
                            .src()
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "[?]".to_owned()),
                        packet
                            .dst()
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "[?]".to_owned()),
                    );
                    for chunk in packet.data().chunks(16) {
                        for (i, b) in chunk.iter().enumerate() {
                            print!(
                                "{}{b:02x}",
                                if i == 0 { "    " } else { " " }
                            );
                        }
                        println!();
                    }
                }
                if packet.data() == frame_ {
                    return Ok(true);
                }
            }
        }
        if verbose {
            println!("Timeout while waiting for matching packet");
        }
        Ok(false)
    });

    rx.recv().unwrap();

    // Open the DLPI interface
    let mut iface_send = dlpi::Dlpi::open(interface_name)?;
    iface_send.bind_ethertype(u32::from(EtherTypes::Ipv6.0))?;
    iface_send.send(
        dlpi::Address {
            addr: [0x33, 0x33, 0x1, 0xde, 0x0, 0x2], // multicast
        },
        &frame,
    )?;
    let out = rx_handle.join().unwrap()?;
    if out {
        println!("Success: loopback detected");
    } else {
        bail!("No loopback detected");
    }

    Ok(())
}

pub fn construct_icmpv6_frame(
    src_ipv6: Ipv6Addr,
    dest_ipv6: Ipv6Addr,
    data: &[u8; 56],
    identifier: u16,
    sequence: u16,
) -> Result<Vec<u8>> {
    // Calculate sizes
    const ICMPV6_HEADER_SIZE: usize = 8;
    const IPV6_HEADER_SIZE: usize = 40;

    let icmpv6_payload_size = ICMPV6_HEADER_SIZE + data.len();
    let total_size = IPV6_HEADER_SIZE + icmpv6_payload_size;

    // Create buffer for the entire frame
    let mut buffer = vec![0; total_size];

    // Create echo request at correct offset
    let mut echo_req = echo_request::MutableEchoRequestPacket::new(
        &mut buffer[IPV6_HEADER_SIZE..],
    )
    .unwrap();
    echo_req.set_icmpv6_type(Icmpv6Types::EchoRequest);
    echo_req.set_icmpv6_code(pnet::packet::icmpv6::Icmpv6Code(0));
    echo_req.set_identifier(identifier);
    echo_req.set_sequence_number(sequence);
    echo_req.set_payload(data);

    // Calculate ICMPv6 checksum
    let icmpv6_immutable =
        Icmpv6Packet::new(&buffer[IPV6_HEADER_SIZE..]).unwrap();
    let checksum = pnet::packet::icmpv6::checksum(
        &icmpv6_immutable,
        &src_ipv6,
        &dest_ipv6,
    );

    // Reborrow to set the checksum
    let mut icmpv6_packet =
        MutableIcmpv6Packet::new(&mut buffer[IPV6_HEADER_SIZE..]).unwrap();
    icmpv6_packet.set_checksum(checksum);

    // Build the IPv6 header at the front of the buffer
    let mut ipv6_packet = MutableIpv6Packet::new(&mut buffer).unwrap();
    ipv6_packet.set_version(6);
    ipv6_packet.set_traffic_class(0);
    ipv6_packet.set_flow_label(0);
    ipv6_packet.set_payload_length(icmpv6_payload_size as u16);
    ipv6_packet
        .set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ipv6_packet.set_hop_limit(64);
    ipv6_packet.set_source(src_ipv6);
    ipv6_packet.set_destination(dest_ipv6);
    // Payload is already populated in the buffer

    Ok(buffer)
}
