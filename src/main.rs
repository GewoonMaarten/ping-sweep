use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::IoSlice;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};
use std::{default, mem};
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

impl From<[u8; IPV4_DATAGRAM_SIZE]> for ICMPPacket {
    fn from(buf: [u8; IPV4_DATAGRAM_SIZE]) -> Self {
        let packet = &buf[IPV4_HEADER_SIZE..IPV4_DATAGRAM_SIZE];
        let payload: [u8; ICMP_PAYLOAD_SIZE] = packet[8..ICMP_PACKET_SIZE].try_into().unwrap();
        Self {
            r#type: packet[0],
            code: packet[1],
            checksum: (packet[2] as u16) << 8 | packet[3] as u16,
            id: (packet[4] as u16) << 8 | packet[5] as u16,
            seq: (packet[6] as u16) << 8 | packet[7] as u16,
            payload,
        }
    }
}

#[derive(Debug)]
pub struct EchoRequest {
    pub request_packet: ICMPPacket,
    pub response_packet: Option<ICMPPacket>,
    pub addr: SocketAddrV4,
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

fn send_ping_to(socket: &Arc<Socket>, echo_request: &EchoRequest) -> Result<Vec<usize>, std::io::Error> {
    const MESSAGE_SIZE: usize = 1024;
    
    let packet_slice = echo_request.request_packet.as_slice();
    let mut msgs = Vec::with_capacity(MESSAGE_SIZE);
    let mut addrs = Vec::with_capacity(MESSAGE_SIZE);

    for _ in 0..MESSAGE_SIZE {
        msgs.push(IoSlice::new(&packet_slice));
        addrs.push(socket2::SockAddr::from(echo_request.addr));
    }

    loop {
        let result = socket.send_multiple_to(&msgs, &addrs, 0);
        match result {
            Err(e) => match e.raw_os_error() {
                // Some(105) => (),
                // Some(11) => (),
                _ => {
                    println!("{:?}", e);
                    return Err(e);
                }
            },
            Ok(e) => {
                if e.len() != MESSAGE_SIZE
                {
                    panic!("holdup");
                }
                return Ok(e);
            },
        }
    }
}

fn main() {
    let (pps_tx, pps_rx) = std::sync::mpsc::channel();

    let mut threads = vec![];
    for _ in 0..5
    {        
        let sender_tx = std::sync::mpsc::Sender::clone(&pps_tx);

        let socket = Arc::clone(&icmp_socket());
        let sender_socket = socket.clone();
        let sender = thread::spawn(move || {    
            let ip = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
            let addr = SocketAddrV4::new(ip, 0);
        
            loop {
                let echo_request = EchoRequest {
                    request_packet: ICMPPacket::new(HDR_TYP_ECHO, HDR_CFG_ECHO, 1, 1),
                    response_packet: None,
                    addr: addr,
                    send_time: Instant::now(),
                    round_trip_time: None,
                };
                let _ = send_ping_to(&sender_socket, &echo_request);
                sender_tx.send(1024).unwrap();
            }
        });
        threads.push(sender);
    }

    // Calculate packet statistics
    let mut now_pps: u64 = 0;
    let mut last_pps: u64 = 0;
    let interval = Duration::from_secs(1);
    let mut start = Instant::now();
    loop 
    {
        now_pps += pps_rx.recv().unwrap();

        let now = Instant::now();
        let next_stop = start + interval;
        if now >= next_stop
        {
            let delta_pps = (now_pps - last_pps) as f64 / (now - start).as_secs_f64();
            last_pps = now_pps;
            println!("{:.2}K pps", delta_pps / 1000.0);
            start = next_stop;
        }
    }
        
        
                // let mut receive_buf: [MaybeUninit<u8>; IPV4_DATAGRAM_SIZE] =
                //     unsafe { MaybeUninit::uninit().assume_init() };
                // let (reply_size, _) = socket.recv_from(&mut receive_buf).unwrap();
                // if reply_size != IPV4_DATAGRAM_SIZE {
                //     println!("huh?");
                // }
                // let reply_data = unsafe { mem::transmute::<_, [u8; IPV4_DATAGRAM_SIZE]>(receive_buf) };
                // echo_request.response_packet = Some(ICMPPacket::from(reply_data));
                // echo_request.round_trip_time = Some(Instant::now().duration_since(echo_request.send_time));
                // // println!("time={:?}", echo_request.round_trip_time.unwrap());
        
                // thread::sleep(Duration::from_millis(500));
    // let socket = Arc::clone(&arc_socket);
    // let receiver = thread::spawn(move || {
    //     let mut file = std::fs::OpenOptions::new().create(true).append(true).open("pings.txt").unwrap();
    //     loop
    //     {
    //         let mut receive_buf = [MaybeUninit::uninit(); 1024];
    //         let result = socket.recv_from(&mut receive_buf);
    //         match result
    //         {
    //             Err(_) => return,
    //             Ok(a) => {
    //                 writeln!(file, "{:?}", a.1.as_socket().unwrap().ip());
    //             }
    //         };
    //     }
    // });

    // sender.join().unwrap();
    // receiver.join().unwrap();

    // let result = socket.recv_from(&mut receive_buf).unwrap();
    // println!(
    //     "received {:?} bytes of data from {:?}",
    //     result.0,
    //     result.1.as_socket().unwrap().ip()
    // );
}

// use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
// use socket2::{Domain, Protocol, Socket, Type};
// use std::net::Ipv4Addr;
// use std::net::SocketAddrV4;
// use tokio::fs::OpenOptions;
// use tokio::io::unix::AsyncFd;
// use tokio::io::{AsyncWriteExt, Interest};

// #[tokio::main]
// async fn main() -> std::io::Result<()> {
//     const IP_COUNT: u64 = 256 * 256 * 256 * 256;

//     let multi_progress = MultiProgress::new();
//     let style = ProgressStyle::with_template(
//         "{spinner} [{elapsed_precise}] [{bar}] ({pos}/{len}, {per_sec}, ETA {eta})",
//     )
//     .unwrap();
//     let pb1 = multi_progress.add(ProgressBar::new(IP_COUNT));
//     pb1.set_style(style.clone());
//     let pb2 = multi_progress.add(ProgressBar::new(IP_COUNT));
//     pb2.set_style(style.clone());
//     let pb3 = multi_progress.add(ProgressBar::new(IP_COUNT));
//     pb3.set_style(style.clone());

//     let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
//     socket.set_nonblocking(true).unwrap();
//     let socket = AsyncFd::new(socket).unwrap();
//     let socket = Arc::new(socket);

//     let (tx, mut rx) = tokio::sync::mpsc::channel::<(u8, u8, u8, u8)>(10000);

//     let producer = tokio::spawn(async move {
        // for a in 0..=255 {
        //     for b in 0..=255 {
        //         for c in 0..=255 {
        //             for d in 0..=255 {
        //                 tx.send((a, b, c, d)).await.unwrap();
        //                 pb1.inc(1);
        //             }
        //         }
        //     }
        // }
//         pb1.finish();
//     });

//     let socket1 = socket.clone();
//     let worker = tokio::spawn(async move {
//         while let Some(ip) = rx.recv().await {
//             let ip: Ipv4Addr = Ipv4Addr::new(ip.0, ip.1, ip.2, ip.3);
//             let addr: SocketAddrV4 = SocketAddrV4::new(ip, 0);
//             let packet = create_echo_pkt(1, 2);

//             loop {
//                 let guard = socket1.ready(Interest::WRITABLE).await.unwrap();
//                 if guard.ready().is_writable() {
//                     let result = socket1
//                         .async_io(Interest::WRITABLE, |socket| {
//                             socket.send_to(&packet, &socket2::SockAddr::from(addr))
//                         })
//                         .await;
//                     match result {
//                         Err(e) => match e.raw_os_error() {
//                             // Some(105) => println!("{:?}", e),
//                             _ => (),
//                         },
//                         Ok(_) => {
//                             pb2.inc(1);
//                             break;
//                         }
//                     };
//                 }
//             }
//         }
//         pb2.finish();
//     });

//     let socket2 = socket.clone();
//     let writer = tokio::spawn(async move {
//         let mut file = OpenOptions::new()
//             .append(true)
//             .create(true)
//             .open("pings_2.txt")
//             .await
//             .unwrap();

//         loop {
//             let mut buf = [MaybeUninit::uninit(); 1024];
//             let result = socket2
//                 .async_io(Interest::READABLE, |socket| socket.recv_from(&mut buf))
//                 .await;
//             match result {
//                 Err(_) => return,
//                 Ok(a) => {
//                     let data = format!("{:?}\n", a.1.as_socket().unwrap().ip());
//                     file.write_all(data.as_bytes()).await.unwrap();
//                     pb3.inc(1);
//                 }
//             }
//         }
//     });

//     producer.await.unwrap();
//     worker.await.unwrap();
//     writer.await.unwrap();

//     Ok(())
// }
