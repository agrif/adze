use std::io::{Read, Write};
use std::net::TcpStream;

use adze::aprs;
use adze::ax25;
use adze::kiss;

#[derive(clap::Parser, Debug)]
struct ToolOpts {
    #[command(subcommand)]
    command: ToolCommand,
}

#[derive(clap::Subcommand, Debug)]
enum ToolCommand {
    Pcap(PcapOpts),
    Decode(DecodeOpts),
    Message(MessageOpts),
    PingServer(PingServerOpts),
}

fn main() -> anyhow::Result<()> {
    use clap::Parser;
    use ToolCommand::*;

    let opts = ToolOpts::parse();
    match opts.command {
        Pcap(o) => o.run(),
        Decode(o) => o.run(),
        Message(o) => o.run(),
        PingServer(o) => o.run(),
    }
}

fn log_packet_header<T>(packet: &ax25::Packet<T>) {
    println!();
    print!("{}>{}", packet.source.address, packet.destination.address);

    for part in &packet.path {
        print!(",{}", part.address);
        if part.flag {
            print!("*");
        }
    }
}

fn log_packet<T>(packet: &ax25::Packet<T>)
where
    T: AsRef<[u8]>,
{
    log_packet_header(packet);
    print!(" {}", packet.control.frame_type().name());
    if let Some(protocol) = packet.control.frame_type().protocol() {
        println!("/{:?}", protocol);
    } else {
        println!();
    }

    if !packet.information.as_ref().is_empty() {
        let cfg = pretty_hex::HexConfig {
            title: false,
            ..Default::default()
        };
        println!("{}", pretty_hex::config_hex(&packet.information, cfg));
    }
}

fn log_packet_aprs<T>(packet: &ax25::Packet<aprs::Packet<T>>)
where
    T: AsRef<str>,
{
    log_packet_header(packet);
    println!(" APRS");

    match &packet.information {
        aprs::Packet::Message {
            destination,
            text,
            number,
        } => {
            println!("message to {}", destination);
            println!("{}", text.as_ref());
            if let Some(number) = number {
                println!("(number {})", number);
            }
        }

        aprs::Packet::MessageAck {
            destination,
            number,
        } => {
            println!("message ack to {}", destination);
            println!("number {}", number);
        }

        aprs::Packet::MessageRej {
            destination,
            number,
        } => {
            println!("message rej to {}", destination);
            println!("number {}", number);
        }
    }
}

#[derive(clap::Args, Debug)]
struct PcapOpts {
    #[arg()]
    pcapfile: std::path::PathBuf,
    #[arg(default_value = "localhost:8001")]
    address: String,
}

impl PcapOpts {
    fn run(self) -> anyhow::Result<()> {
        let mut decoder = kiss::Decoder::new();

        let output = std::fs::File::create(&self.pcapfile)?;
        let mut output = pcap_file::pcap::PcapWriter::with_header(
            output,
            pcap_file::pcap::PcapHeader {
                datalink: pcap_file::DataLink::AX25,
                ..Default::default()
            },
        )?;

        let mut stream = TcpStream::connect(&self.address)?;

        let mut buf = [0; 512];
        loop {
            let amt = stream.read(&mut buf)?;
            if amt == 0 {
                break;
            }

            let mut received = &buf[..amt];
            while let Some(frame) = decoder.decode(&mut received) {
                match frame {
                    Ok(kiss::Message::Data(_, data)) => {
                        output.write_packet(&pcap_file::pcap::PcapPacket {
                            timestamp: std::time::SystemTime::UNIX_EPOCH.elapsed()?,
                            orig_len: data.len() as u32,
                            data: data.into(),
                        })?;

                        match ax25::Packet::parse(data) {
                            Ok(packet) => log_packet(&packet),
                            Err(e) => println!("error: {}", e),
                        }
                    }
                    Ok(_) => (),
                    Err(e) => println!("error: {}", e),
                }
            }
        }

        Ok(())
    }
}

#[derive(clap::Args, Debug)]
struct DecodeOpts {
    #[arg(default_value = "localhost:8001")]
    address: String,
}

impl DecodeOpts {
    fn run(self) -> anyhow::Result<()> {
        let mut decoder = kiss::Decoder::new();
        let mut stream = TcpStream::connect(self.address)?;

        let mut buf = [0; 512];
        loop {
            let amt = stream.read(&mut buf)?;
            if amt == 0 {
                break;
            }

            let mut received = &buf[..amt];
            while let Some(frame) = decoder.decode(&mut received) {
                match frame {
                    Ok(kiss::Message::Data(_, data)) => match ax25::Packet::parse(data) {
                        Ok(packet) => match aprs::Packet::parse(&packet) {
                            Ok(apacket) => {
                                log_packet_aprs(&packet.map(|_| apacket));
                            }
                            Err(e) => {
                                log_packet(&packet);
                                if e != aprs::ParseError::NotAprs {
                                    println!("error: {}", e);
                                }
                            }
                        },
                        Err(e) => println!("error: {}", e),
                    },
                    Ok(_) => (),
                    Err(e) => println!("error: {}", e),
                }
            }
        }

        Ok(())
    }
}

#[derive(clap::Args, Debug)]
struct MessageOpts {
    source: String,
    destination: String,
    message: String,
    #[arg(default_value = "localhost:8001")]
    address: String,
}

impl MessageOpts {
    fn run(self) -> anyhow::Result<()> {
        let mut encoder = kiss::Encoder::new();

        let msg = aprs::Packet::Message {
            destination: self.destination.parse()?,
            text: self.message,
            number: None,
        };

        let packet = ax25::Packet {
            destination: "APZADZ".parse()?,
            source: self.source.parse()?,
            //path: (&["WIDE1-1".parse().unwrap(), "WIDE2-1".parse().unwrap()] as &[_]).try_into()?,
            path: Default::default(),
            control: ax25::Control::u_ui(false, ax25::Protocol::None),
            information: msg,
        };

        let frame = kiss::Message::Data(kiss::Port::P0, packet);
        let data = encoder.encode(&frame)?;

        let mut stream = TcpStream::connect(&self.address)?;
        stream.write_all(data)?;

        Ok(())
    }
}

#[derive(clap::Args, Debug)]
struct PingServerOpts {
    station: String,
    #[arg(default_value = "localhost:8001")]
    address: String,
}

impl PingServerOpts {
    fn run(self) -> anyhow::Result<()> {
        let stream = TcpStream::connect(self.address)?;
        let mut server = PingServer::new(self.station, stream)?;

        server.run()
    }
}

#[derive(Debug)]
pub struct PingServer {
    station: String,
    station_address: ax25::Address,
    stream: TcpStream,
    last_message: std::time::Instant,
    timeout: std::time::Duration,
    next_number: usize,
    threads: weak_table::WeakValueHashMap<ax25::Address, std::sync::Weak<PingServerThread>>,
}

impl PingServer {
    pub fn new(station: String, stream: TcpStream) -> anyhow::Result<Self> {
        Ok(PingServer {
            station_address: station.parse()?,
            station,
            stream,
            last_message: std::time::Instant::now(),
            timeout: std::time::Duration::from_secs(30),
            next_number: 0,
            threads: Default::default(),
        })
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        let mut decoder = kiss::Decoder::new();

        let mut buf = [0; 512];
        loop {
            let amt = self.stream.read(&mut buf)?;
            if amt == 0 {
                break;
            }

            let mut received = &buf[..amt];
            while let Some(frame) = decoder.decode(&mut received) {
                match frame {
                    Ok(kiss::Message::Data(port, data)) => {
                        if let Err(e) = self.handle_frame(port, data) {
                            println!("error: {}", e);
                        }
                    }
                    Ok(_) => (),
                    Err(e) => println!("error: {}", e),
                }
            }
        }
        Ok(())
    }

    fn handle_frame(&mut self, port: kiss::Port, data: &[u8]) -> anyhow::Result<()> {
        let packet = ax25::Packet::parse(data)?;
        match aprs::Packet::parse(&packet) {
            Ok(ap) => self.handle_aprs(port, packet.map(|_| ap)),
            Err(_) => Ok(()),
        }
    }

    fn handle_aprs(
        &mut self,
        port: kiss::Port,
        packet: ax25::Packet<aprs::Packet<&str>>,
    ) -> anyhow::Result<()> {
        match packet.information {
            aprs::Packet::Message {
                destination,
                text,
                number,
            } => {
                if destination.eq_ignore_ascii_case(&self.station) {
                    self.handle_message(port, packet, text, &number)?;
                }
            }

            aprs::Packet::MessageAck {
                destination,
                number,
            } => {
                if destination.eq_ignore_ascii_case(&self.station) {
                    self.handle_ack_rej(port, packet, &number)?;
                }
            }

            aprs::Packet::MessageRej {
                destination,
                number,
            } => {
                if destination.eq_ignore_ascii_case(&self.station) {
                    self.handle_ack_rej(port, packet, &number)?;
                }
            }

            _ => (),
        }

        Ok(())
    }

    fn send_ack(
        &mut self,
        port: kiss::Port,
        destination: &ax25::Address,
        number: &aprs::MessageNumber,
    ) -> anyhow::Result<()> {
        let mut encoder = kiss::Encoder::new();

        let msg: aprs::Packet<String> = aprs::Packet::MessageAck {
            destination: format!("{}", destination).parse()?,
            number: *number,
        };

        let packet = ax25::Packet {
            destination: "APZADZ".parse()?,
            source: self.station_address.clone().into(),
            path: (&["WIDE1-1".parse().unwrap(), "WIDE2-1".parse().unwrap()] as &[_]).try_into()?,
            control: ax25::Control::u_ui(false, ax25::Protocol::None),
            information: msg,
        };

        log_packet_aprs(&packet);

        let frame = kiss::Message::Data(port, packet);
        let data = encoder.encode(&frame)?;

        self.stream.write_all(data)?;
        Ok(())
    }

    fn handle_message(
        &mut self,
        port: kiss::Port,
        packet: ax25::Packet<aprs::Packet<&str>>,
        text: &str,
        number: &Option<aprs::MessageNumber>,
    ) -> anyhow::Result<()> {
        let text = text.trim();
        if ["ping", "ping?", "?ping", "?ping?"]
            .iter()
            .any(|m| text.eq_ignore_ascii_case(m))
        {
            // this is a ping request
            log_packet_aprs(&packet);
            println!("got ping request from {}", packet.source.address);

            // rate limit
            if self.last_message.elapsed() < self.timeout {
                println!("bail: rate limit.");
                return Ok(());
            }

            // update rate limit
            self.last_message = std::time::Instant::now();

            // send an ack if requested
            if let Some(number) = number {
                self.send_ack(port, &packet.source.address, number)?;
            }

            // check if outstanding thread
            let source = packet.source.address.clone();
            if self.threads.contains_key(&source) {
                println!("bail: outstanding thread.");
                return Ok(());
            }

            // create a new thread
            let packet = packet.map(|p| p.into_owned());
            let thread = PingServerThread::spawn(
                port,
                self.station_address.clone(),
                packet,
                self.next_number,
                number.is_some(),
                self.stream.try_clone()?,
            )?;
            self.next_number += 1;
            self.threads.insert(source, thread);
        }
        Ok(())
    }

    fn handle_ack_rej(
        &mut self,
        port: kiss::Port,
        packet: ax25::Packet<aprs::Packet<&str>>,
        number: &aprs::MessageNumber,
    ) -> anyhow::Result<()> {
        if let Some(thread) = self.threads.get(&packet.source.address) {
            if thread.wait_for_ack && &thread.number == number {
                // we have an active thread and this ack/rej matches it
                log_packet_aprs(&packet);
                thread.sender.send(())?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct PingServerThread {
    port: kiss::Port,
    station: ax25::Address,
    packet: ax25::Packet<aprs::Packet<String>>,
    number: aprs::MessageNumber,
    wait_for_ack: bool,
    sender: std::sync::mpsc::Sender<()>,
}

impl PingServerThread {
    fn spawn(
        port: kiss::Port,
        station: ax25::Address,
        packet: ax25::Packet<aprs::Packet<String>>,
        number: usize,
        wait_for_ack: bool,
        stream: TcpStream,
    ) -> anyhow::Result<std::sync::Arc<Self>> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let thread = std::sync::Arc::new(Self {
            port,
            station,
            packet,
            number: format!("{:03}", number % 1000).parse()?,
            wait_for_ack,
            sender,
        });

        let inside = thread.clone();
        std::thread::spawn(move || {
            if let Err(e) = inside.run(stream, receiver) {
                println!("error: {}", e);
            }
        });

        Ok(thread)
    }

    fn run(
        &self,
        mut stream: TcpStream,
        receiver: std::sync::mpsc::Receiver<()>,
    ) -> anyhow::Result<()> {
        println!("[thread {}] started", self.packet.source.address);

        std::thread::sleep(std::time::Duration::from_secs(4));
        self.send_reply(&mut stream)?;

        if self.wait_for_ack {
            println!("[thread {}] waiting for ack", self.packet.source.address);
            for wait in 0..6 {
                let secs = (1 << wait) * 6;
                match receiver.recv_timeout(std::time::Duration::from_secs(secs)) {
                    Ok(()) => {
                        println!("[thread {}] received ack", self.packet.source.address);
                        break;
                    }

                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        println!(
                            "[thread {}] retrying after {} seconds",
                            self.packet.source.address, secs
                        );
                        self.send_reply(&mut stream)?;
                    }

                    Err(e) => {
                        // other side hung up
                        Err(e)?
                    }
                }
            }
        }

        println!("[thread {}] exiting", self.packet.source.address);
        Ok(())
    }

    fn send_reply(&self, stream: &mut TcpStream) -> anyhow::Result<()> {
        let mut encoder = kiss::Encoder::new();

        let mut text = format!(
            "pong: {}>{}",
            self.packet.source.address, self.packet.destination.address
        );
        for part in &self.packet.path {
            text += &format!(",{}", part.address);
            if part.flag {
                text += "*"
            }
        }

        let msg = aprs::Packet::Message {
            destination: format!("{}", self.packet.source.address).parse()?,
            text,
            number: if self.wait_for_ack {
                Some(self.number)
            } else {
                None
            },
        };

        let packet = ax25::Packet {
            destination: "APZADZ".parse()?,
            source: self.station.clone().into(),
            path: (&["WIDE1-1".parse().unwrap(), "WIDE2-1".parse().unwrap()] as &[_]).try_into()?,
            control: ax25::Control::u_ui(false, ax25::Protocol::None),
            information: msg,
        };

        log_packet_aprs(&packet);

        let frame = kiss::Message::Data(self.port, packet);
        let data = encoder.encode(&frame)?;

        stream.write_all(data)?;

        Ok(())
    }
}
