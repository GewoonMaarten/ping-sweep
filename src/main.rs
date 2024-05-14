use socket2::{Domain, Protocol, Socket, Type};
use std::fs::OpenOptions;
use std::io::{IoSlice, Seek, Write};
use std::mem;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};
use std::{mem::MaybeUninit, sync::Arc, thread};

#[derive(Debug)]
#[repr(C, packed)]
pub struct ICMPPacket {
    pub r#type: u8,
    pub code: u8,
    pub checksum: u16,
    pub id: u16,
    pub seq: u16,
    pub payload: [u8; ICMP_PAYLOAD_SIZE],
}
const IPV4_HEADER_SIZE: usize = 20;
const ICMP_PAYLOAD_SIZE: usize = 20;
const ICMP_PACKET_SIZE: usize = core::mem::size_of::<ICMPPacket>();
const IPV4_DATAGRAM_SIZE: usize = IPV4_HEADER_SIZE + ICMP_PACKET_SIZE;

impl ICMPPacket {
    pub fn new(r#type: u8, code: u8, id: u16, seq: u16) -> Self {
        let mut packet = Self {
            r#type,
            code,
            checksum: 0,
            id,
            seq,
            payload: [0u8; ICMP_PAYLOAD_SIZE],
        };
        packet.checksum = packet.calc_checksum();
        packet
    }

    pub fn as_slice(&self) -> [u8; ICMP_PACKET_SIZE] {
        let mut buf = [0u8; ICMP_PACKET_SIZE];
        buf[0] = self.r#type;
        buf[1] = self.code;
        buf[2] = (self.checksum >> 8) as u8;
        buf[3] = self.checksum as u8;
        buf[4] = (self.id >> 8) as u8;
        buf[5] = self.id as u8;
        buf[6] = (self.seq >> 8) as u8;
        buf[7] = self.seq as u8;
        buf
    }

    fn calc_checksum(&self) -> u16 {
        let buf = self.as_slice();
        let mut sum = 0u32;
        for word in buf.chunks(2) {
            let mut part = u16::from(word[0]) << 8;
            if word.len() > 1 {
                part += u16::from(word[1]);
            }
            sum = sum.wrapping_add(u32::from(part));
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !sum as u16
    }
}

impl TryFrom<[u8; IPV4_DATAGRAM_SIZE]> for ICMPPacket {
    fn try_from(buf: [u8; IPV4_DATAGRAM_SIZE]) -> Result<ICMPPacket, String> {
        let packet = &buf[IPV4_HEADER_SIZE..IPV4_DATAGRAM_SIZE];
        let payload: [u8; ICMP_PAYLOAD_SIZE] = packet[8..ICMP_PACKET_SIZE].try_into().unwrap();
        let packet = Self {
            r#type: packet[0],
            code: packet[1],
            checksum: (packet[2] as u16) << 8 | packet[3] as u16,
            id: (packet[4] as u16) << 8 | packet[5] as u16,
            seq: (packet[6] as u16) << 8 | packet[7] as u16,
            payload,
        };
        if packet.code == 0 && packet.r#type == 0 {
            Ok(packet)
        } else {
            Err("Expected code and/or type to be 0".to_string())
        }
    }

    type Error = String;
}

#[derive(Debug)]
pub struct EchoRequest {
    pub request_packet: ICMPPacket,
    pub response_packet: Option<ICMPPacket>,
    pub send_time: Instant,
    pub round_trip_time: Option<Duration>,
}

/// An ICMP header type indicating the message is an Echo request.
const HDR_TYP_ECHO: u8 = 8;
/// An ICMP header configuration indicating the Echo message contains an id and sequence number.
const HDR_CFG_ECHO: u8 = 0;

fn icmp_socket() -> Arc<Socket> {
    let socket: Socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
    Arc::new(socket)
}

fn main() {
    const BATCH_SIZE: usize = 1024;
    const N_THREADS: usize = 1;

    let (ip_tx, ip_rx) = mpsc::sync_channel::<Vec<socket2::SockAddr>>(N_THREADS);
    let (pps_tx, pps_rx) = mpsc::channel();

    let ip_rx = Arc::new(Mutex::new(ip_rx));

    for i in 0..N_THREADS {
        let sender_ip_rx = Arc::clone(&ip_rx);
        let sender_tx = std::sync::mpsc::Sender::clone(&pps_tx);

        let socket = Arc::clone(&icmp_socket());
        let sender_socket = socket.clone();
        let _sender = thread::spawn(move || {
            loop {
                if let Ok(batch) = sender_ip_rx.lock().unwrap().recv() {
                    let echo_request = EchoRequest {
                        request_packet: ICMPPacket::new(HDR_TYP_ECHO, HDR_CFG_ECHO, 1, 1),
                        response_packet: None,
                        send_time: Instant::now(),
                        round_trip_time: None,
                    };
                    let packet_slice = echo_request.request_packet.as_slice();
                    let mut msgs = Vec::with_capacity(BATCH_SIZE);
                    for _ in 0..BATCH_SIZE {
                        msgs.push(IoSlice::new(&packet_slice));
                    }

                    loop {
                        let result = sender_socket.send_multiple_to(&msgs, &batch, 0);
                        match result {
                            Err(e) => match e.raw_os_error() {
                                Some(105) => continue,
                                // Some(11) => (),
                                _ => {
                                    panic!("{:?}", e);
                                }
                            },
                            Ok(e) => {
                                if e.len() != msgs.len() {
                                    msgs.drain(0..e.len());
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    sender_tx.send(BATCH_SIZE).unwrap();
                }
            }
        });

        let receiver_socket = socket.clone();
        let _receiver = thread::spawn(move || {
            let mut f = OpenOptions::new()
                .append(true)
                .create(true) // Optionally create the file if it doesn't already exist
                .open(format!("pings_t{}.txt", i))
                .expect("Unable to open file");
            loop {
                let mut receive_buf: [MaybeUninit<u8>; IPV4_DATAGRAM_SIZE] =
                    unsafe { MaybeUninit::uninit().assume_init() };
                let (reply_size, addr) = receiver_socket.recv_from(&mut receive_buf).unwrap();
                if reply_size != IPV4_DATAGRAM_SIZE {
                    println!("huh?");
                }
                let reply_data =
                    unsafe { mem::transmute::<_, [u8; IPV4_DATAGRAM_SIZE]>(receive_buf) };
                if let Ok(_) = ICMPPacket::try_from(reply_data) {
                    let sock_addr = addr.as_socket_ipv4().unwrap();
                    let ip = sock_addr.ip();
                    f.write_all(format!("{:?}\n", ip).as_bytes())
                        .expect("Unable to write data");
                }
            }
        });
    }

    // Ip generator
    thread::spawn(move || {
        let total_ips = 256u64.pow(4);
        let total_batches = (total_ips as usize + BATCH_SIZE - 1) / BATCH_SIZE;
        println!("Total batches: {}", total_batches);
        let mut f = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open("pings_gen.txt")
            .expect("Unable to open file");
        let mut current_batch = Vec::new();
        for a in 0..=255 {
            for b in 0..=255 {
                for c in 0..=255 {
                    for d in 0..=255 {
                        let ip = Ipv4Addr::new(a, b, c, d);
                        let addr = SocketAddrV4::new(ip, 0);
                        let addr = socket2::SockAddr::from(addr);
                        current_batch.push(addr);
                        if current_batch.len() >= BATCH_SIZE {
                            ip_tx.send(current_batch.clone()).unwrap();
                            current_batch.clear();

                            f.seek(std::io::SeekFrom::Start(0)).unwrap();
                            f.write_all(format!("{}.{}.{}.{}", a, b, c, d).as_bytes())
                                .expect("Unable to write data");
                            f.flush().unwrap();
                        }
                    }
                }
            }
        }

        // Send remaining IPs
        if !current_batch.is_empty() {
            ip_tx.send(current_batch).unwrap();
        }
    });

    let total_ips = 256u64.pow(4);

    // Calculate packet statistics
    let mut now_pps: u64 = 0;
    let mut last_pps: u64 = 0;
    let interval = Duration::from_secs(1);
    let mut start = Instant::now();

    while let Ok(pps) = pps_rx.recv() {
        // println!("received: {}", pps);
        now_pps += pps as u64;
        let now = Instant::now();
        let next_stop = start + interval;
        if now >= next_stop {
            let delta_pps = (now_pps - last_pps) as f64 / (now - start).as_secs_f64();
            last_pps = now_pps;
            println!(
                "{:.2}K pps, {:.2}M total packets, {:.4}% sent, {:.1} min until complete",
                delta_pps / 1000.0,
                now_pps as f64 / 1000.0 / 1000.0,
                (now_pps as f64 / total_ips as f64) * 100.0,
                ((total_ips - now_pps) as f64 / delta_pps) / 60.0
            );
            start = next_stop;
        }
    }
}
