use anyhow::Result;
use bootserver::dlpi::{Address, Dlpi};
use std::env;
use std::thread;

const DLSEND_SAP: u32 = 0xdeed;
const DLSEND_MSG: &str = "A Elbereth Gilthoniel";

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <interface_name>", args[0]);
        std::process::exit(1);
    }

    let interface_name = args[1].to_owned();

    // Find the network interface
    let mut iface_send = Dlpi::open(&interface_name)?;
    iface_send.bind_ethertype(DLSEND_SAP)?;

    let rx_handle = thread::spawn(move || -> Result<()> {
        let mut iface_recv = Dlpi::open(&interface_name)?;
        iface_recv.bind_ethertype(DLSEND_SAP)?;
        for _ in 0..100 {
            if let Ok(Some(packet)) = iface_recv.recv(Some(100)) {
                println!(
                    "got packet from {:?} to {:?} with data {:#x?}",
                    packet.src().map(|p| p.addr),
                    packet.dst().map(|p| p.addr),
                    packet.data(),
                );
            }
        }
        Ok(())
    });

    iface_send.send(Address { addr: [0xFF; 6] }, DLSEND_MSG.as_bytes())?;
    rx_handle.join().unwrap().unwrap();

    Ok(())
}
