use pnet::datalink;
use pnet::datalink::Channel;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ipv4::Ipv4Packet;
use rand::Rng;
use std::env;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <interface_name>", args[0]);
        std::process::exit(1);
    }

    let interface_name = &args[1];

    // Find the network interface
    let interfaces = datalink::interfaces();
    let iface = match interfaces.iter().find(|i| i.name == *interface_name) {
        Some(i) => i,
        None => {
            eprintln!("Interface '{}' not found", interface_name);
            std::process::exit(1);
        }
    };

    println!("Testing interface: {}", iface.name);
    println!("MAC address: {}", iface.mac.unwrap());

    // Create channels for sending and receiving
    let (mut tx, mut rx) = match datalink::channel(iface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("Unsupported channel type");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to create channel: {}", e);
            std::process::exit(1);
        }
    };

    // Shared state for tracking packets
    let seen_payloads = Arc::new(Mutex::new(Vec::new()));
    let rx_payloads = Arc::new(Mutex::new(Vec::new()));

    let rx_clone = rx_payloads.clone();

    // Spawn receiver thread
    let receiver_handle = thread::spawn(move || {
        for _ in 0..100 {
            if let Ok(packet) = rx.next() {
                if let Some(payload) = extract_icmp_payload(&packet) {
                    let mut rx_vec = rx_clone.lock().unwrap();
                    println!("Received ICMP packet with payload {payload:x?}");
                    rx_vec.push(payload);
                }
            }
        }
    });

    // Give receiver thread time to start
    thread::sleep(Duration::from_millis(100));

    // Generate random payloads for test packets
    let mut rng = rand::rng();
    println!("\nSending test packets...");

    for i in 0..5 {
        let payload: [u8; 32] = rng.random();
        println!("Sending packet {} with payload: {:02x?}", i, &payload[..8]);

        {
            let mut seen = seen_payloads.lock().unwrap();
            seen.push(payload.to_vec());
        }

        // Create and send a packet with this payload
        send_icmp_ping(iface, &mut tx, &payload);
        thread::sleep(Duration::from_millis(500));
    }

    // Wait for receiver thread
    receiver_handle.join().unwrap();

    // Analyze results
    println!("\n=== Analysis ===");
    let seen = seen_payloads.lock().unwrap();
    let received = rx_payloads.lock().unwrap();

    println!("Sent {} packets", seen.len());
    println!("Received {} packets", received.len());

    let mut loopback_count = 0;
    for sent_payload in seen.iter() {
        let matches: Vec<_> = received
            .iter()
            .filter(|recv| recv == &sent_payload)
            .collect();

        if !matches.is_empty() {
            println!(
                "Payload {:02x?}... received {} times",
                &sent_payload[..8],
                matches.len()
            );
            if matches.len() > 1 {
                loopback_count += 1;
            }
        }
    }

    if loopback_count > 0 {
        println!(
            "\n✓ Physical loopback detected! {} packets were echoed back.",
            loopback_count
        );
    } else {
        println!("\n✗ No physical loopback detected.");
    }
}

fn send_icmp_ping(
    iface: &datalink::NetworkInterface,
    tx: &mut Box<dyn datalink::DataLinkSender>,
    payload: &[u8; 32],
) {
    let source_mac = iface.mac.unwrap();
    let dest_mac = source_mac; // Send to self for loopback test

    // Build packet layers bottom-up
    let icmp_packet = create_icmp_echo_request(payload);
    let ipv4_packet = create_ipv4_packet(&icmp_packet);
    let ethernet_packet =
        create_ethernet_packet(source_mac.octets(), dest_mac.octets(), &ipv4_packet);

    if let Err(e) = tx.send_to(&ethernet_packet, None).unwrap() {
        eprintln!("Failed to send packet: {}", e);
    }
}

fn create_icmp_echo_request(payload: &[u8; 32]) -> Vec<u8> {
    let mut packet = vec![0u8; 8 + 32]; // ICMP header + payload
    packet[0] = 8; // Echo Request type
    packet[1] = 0; // Code
    // Checksum at [2..4] - set to 0 for now
    packet[4..6].copy_from_slice(&0u16.to_be_bytes()); // Identifier
    packet[6..8].copy_from_slice(&0u16.to_be_bytes()); // Sequence
    packet[8..].copy_from_slice(payload);

    // Calculate checksum
    let checksum = calculate_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());

    packet
}

fn create_ipv4_packet(icmp_packet: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 20 + icmp_packet.len()];
    packet[0] = 0x45; // Version 4, IHL 5
    packet[1] = 0; // DSCP
    let total_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[4..6].copy_from_slice(&0u16.to_be_bytes()); // Identification
    packet[6..8].copy_from_slice(&0u16.to_be_bytes()); // Flags, Fragment offset
    packet[8] = 64; // TTL
    packet[9] = 1; // Protocol (ICMP)
    // Checksum at [10..12] - calculate below
    let source_ip = [127, 0, 0, 1]; // 127.0.0.1
    let dest_ip = [127, 0, 0, 1];
    packet[12..16].copy_from_slice(&source_ip);
    packet[16..20].copy_from_slice(&dest_ip);
    packet[20..].copy_from_slice(icmp_packet);

    // Calculate IP header checksum
    let checksum = calculate_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    packet
}

fn create_ethernet_packet(src_mac: [u8; 6], dst_mac: [u8; 6], ipv4_packet: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 14 + ipv4_packet.len()];
    packet[0..6].copy_from_slice(&dst_mac);
    packet[6..12].copy_from_slice(&src_mac);
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // EtherType IPv4
    packet[14..].copy_from_slice(ipv4_packet);
    packet
}

fn extract_icmp_payload(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 14 {
        return None;
    }

    // Check EtherType for IPv4
    let ether_type = u16::from_be_bytes([packet[12], packet[13]]);
    if ether_type != 0x0800 {
        return None;
    }

    let ipv4_start = 14;
    if packet.len() < ipv4_start + 20 {
        return None;
    }

    // Check IP protocol for ICMP
    if packet[ipv4_start + 9] != 1 {
        return None;
    }

    let icmp_start = ipv4_start + 20;
    if packet.len() < icmp_start + 40 {
        return None;
    }

    // Check ICMP type (8 = Echo Request, 0 = Echo Reply)
    if packet[icmp_start] != 0 && packet[icmp_start] != 8 {
        return None;
    }

    // Extract the payload (last 32 bytes)
    let payload_start = icmp_start + 8;
    if packet.len() >= payload_start + 32 {
        Some(packet[payload_start..payload_start + 32].to_vec())
    } else {
        None
    }
}

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < data.len() - 1 {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }

    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}
