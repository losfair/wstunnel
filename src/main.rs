mod config;
mod error;

use config::*;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use futures::SinkExt;
use serde::Serialize;
use slab::Slab;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use tokio::{
    fs::File,
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    stream::StreamExt,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex, RwLock,
    },
    time::delay_for,
};
use tokio_tungstenite::{accept_async, tungstenite::Message, WebSocketStream};
use tun::{r#async::DeviceAsync, TunPacket};
use error::*;

const WS_MTU: usize = 1500;

/// CLI options.
#[derive(Debug, StructOpt)]
#[structopt(
    name = "wstunnel",
    about = "WebSocket layer 3 tunnel with authentication"
)]
struct Opt {
    /// Path to config file.
    #[structopt(short = "c", long)]
    config: String,

    /// Listen address.
    #[structopt(short = "l", long)]
    listen: String,

    /// Name of the local TUN device to use.
    #[structopt(short = "t", long)]
    tun: Option<String>,
}

type SessionSet = Arc<RwLock<HashMap<IpAddr, Sender<Vec<u8>>>>>;
type DynPool = Arc<Mutex<Slab<()>>>;

struct Server {
    config: PreparedConfig,
    sessions: SessionSet,
    dyn_v4: DynPool,
    dyn_v6: DynPool,
    tun_w_tx: Sender<Vec<u8>>,
    remaining_bytes: Mutex<u64>,
}

impl Server {
    async fn run_token_bucket_feed(&self) {
        let config = if let Some(ref x) = self.config.rate_limit {
            x
        } else {
            return;
        };

        let base_bp100ms = config
            .base_kbytes_per_sec
            .checked_mul(1024)
            .expect("base_kbytes_per_sec overflow")
            / 10;
        let burst = config
            .burst_kbytes
            .checked_mul(1024)
            .expect("burst_kbytes overflow");

        loop {
            let mut bucket = self.remaining_bytes.lock().await;
            if let Some(x) = bucket.checked_add(base_bp100ms) {
                if x <= burst {
                    *bucket = x;
                }
            }
            drop(bucket);
            delay_for(Duration::from_millis(100)).await;
        }
    }

    async fn take_traffic_allowance(&self, n: u64) -> bool {
        let mut bucket = self.remaining_bytes.lock().await;
        if *bucket >= n {
            *bucket -= n;
            true
        } else {
            false
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), TunError> {
    let opt = Opt::from_args();

    let mut config_file = File::open(&opt.config)
        .await
        .e2s("cannot open config file")?;
    let mut config = String::new();
    config_file
        .read_to_string(&mut config)
        .await
        .e2s("cannot read config")?;
    drop(config_file);
    let config: Config = toml::from_str(&config).e2s("cannot parse config")?;
    let config: PreparedConfig = config.prepare_leaky()?;

    let mut tun_conf = tun::Configuration::default();
    if let Some(ref name) = opt.tun {
        tun_conf.name(name);
    }
    if let Some((ref ipv4, ref mask)) = config.ipv4 {
        tun_conf.address(&ipv4.me);
        tun_conf.netmask(mask.0);
    }
    tun_conf.up();
    let tun_dev = tun::r#async::create_as_async(&tun_conf).e2s("cannot create tun device")?;

    let (tun_w_tx, tun_w_rx) = channel::<Vec<u8>>(128);

    let server: &'static Server = Box::leak(Box::new(Server {
        config,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        dyn_v4: Arc::new(Mutex::new(Slab::new())),
        dyn_v6: Arc::new(Mutex::new(Slab::new())),
        tun_w_tx,
        remaining_bytes: Mutex::new(0),
    }));

    tokio::spawn(server.run_token_bucket_feed());
    tokio::spawn(tun_handler(server, tun_dev, tun_w_rx));

    let mut listener = TcpListener::bind(&opt.listen)
        .await
        .e2s("cannot bind to address")?;
    loop {
        let conn = listener
            .accept()
            .await
            .e2s("cannot accept incoming connection")?;
        tokio::spawn(handle_connection(conn, server));
    }
}

async fn handle_connection((conn, addr): (TcpStream, SocketAddr), server: &'static Server) {
    let stream = match accept_async(conn).await {
        Ok(x) => x,
        Err(e) => {
            println!(
                "{} Failed to accept connection from {:?}: {:?}",
                now(),
                addr,
                e
            );
            return;
        }
    };
    println!("{} New connection from {:?}", now(), addr);

    let (tun_r_tx, tun_r_rx) = channel::<Vec<u8>>(16);
    let mut ipv4_addr: Option<Ipv4Addr> = None;
    let mut ipv6_addr: Option<Ipv6Addr> = None;

    // Allocate address.
    let ipv4_offset = if let Some((ref ipv4, _)) = server.config.ipv4 {
        let mut pool = server.dyn_v4.lock().await;
        if pool.len() != 0 && pool.len() - 1 >= ipv4.dynamic_range_len_minus_one() as usize {
            println!("No IPv4 address available for client {:?}", addr);
            None
        } else {
            let offset = pool.insert(());
            let addr = (offset as u32)
                .checked_add(ipv4.dynamic_range_start())
                .expect("ipv4 offset add overflow");
            assert!(addr <= ipv4.dynamic_range_end());
            drop(pool);

            let addr = Ipv4Addr::from(addr);
            let mut sessions = server.sessions.write().await;
            sessions.insert(IpAddr::V4(addr), tun_r_tx.clone());
            ipv4_addr = Some(addr);
            Some(offset)
        }
    } else {
        None
    };

    let ipv6_offset = if let Some(ref ipv6) = server.config.ipv6 {
        let mut pool = server.dyn_v6.lock().await;
        if pool.len() != 0 && pool.len() - 1 >= ipv6.dynamic_range_len_minus_one() as usize {
            println!("No IPv6 address available for client {:?}", addr);
            None
        } else {
            let offset = pool.insert(());
            let addr = (offset as u128)
                .checked_add(ipv6.dynamic_range_start())
                .expect("ipv6 offset add overflow");
            assert!(addr <= ipv6.dynamic_range_end());
            drop(pool);

            let addr = Ipv6Addr::from(addr);
            let mut sessions = server.sessions.write().await;
            sessions.insert(IpAddr::V6(addr), tun_r_tx.clone());
            ipv6_addr = Some(addr);
            Some(offset)
        }
    } else {
        None
    };

    match do_handle_connection(stream, tun_r_rx, ipv4_addr, ipv6_addr, addr, server).await {
        Ok(()) => {
            println!("{} Terminating connection with {:?}", now(), addr);
        }
        Err(e) => {
            println!(
                "{} Error while handling connection from {:?}: {:?}",
                now(),
                addr,
                e
            );
        }
    }

    if let Some(offset) = ipv4_offset {
        assert!(server
            .sessions
            .write()
            .await
            .remove(&IpAddr::V4(ipv4_addr.unwrap()))
            .is_some());
        server.dyn_v4.lock().await.remove(offset);
    }

    if let Some(offset) = ipv6_offset {
        assert!(server
            .sessions
            .write()
            .await
            .remove(&IpAddr::V6(ipv6_addr.unwrap()))
            .is_some());
        server.dyn_v6.lock().await.remove(offset);
    }
}

async fn do_handle_connection(
    mut stream: WebSocketStream<TcpStream>,
    mut tun_r_rx: Receiver<Vec<u8>>,
    ipv4_addr: Option<Ipv4Addr>,
    ipv6_addr: Option<Ipv6Addr>,
    _peer_addr: SocketAddr,
    server: &'static Server,
) -> Result<(), TunError> {
    #[derive(Serialize, Clone, Debug)]
    struct ClientIpConf<T> {
        address: T,
        gateway: T,
        prefix_length: u8,
    }

    stream
        .send(Message::Text(
            serde_json::json!({
                "ipv4": ipv4_addr.map(|x| {
                    let conf = &server.config.ipv4.as_ref().unwrap().0;
                    ClientIpConf {
                        address: x,
                        gateway: conf.me,
                        prefix_length: conf.prefix_length,
                    }
                }),
                "ipv6": ipv6_addr.map(|x| {
                    let conf = server.config.ipv6.as_ref().unwrap();
                    ClientIpConf {
                        address: x,
                        gateway: conf.me,
                        prefix_length: conf.prefix_length,
                    }
                }),
            })
            .to_string(),
        ))
        .await
        .e2s("cannot send header to client")?;
    let mut tun_w_tx = server.tun_w_tx.clone();
    let mut ping_sent = false;
    loop {
        let stream_fut = stream.next();
        let tun_fut = tun_r_rx.next();
        let timeout_fut = delay_for(Duration::from_secs(10));

        tokio::select! {
            msg = stream_fut => {
                match msg {
                    Some(Ok(Message::Binary(x))) => {
                        if x.len() <= WS_MTU {
                            // Validate source address.
                            let src_addr = match extract_srcaddr(&x) {
                                Ok(x) => x,
                                Err(_) => continue,
                            };
                            let matches = match src_addr {
                                IpAddr::V4(x) => Some(x) == ipv4_addr,
                                IpAddr::V6(x) => Some(x) == ipv6_addr,
                            };
                            if !matches {
                                continue;
                            }
                            tun_w_tx.send(x).await.e2s("cannot send data to tun device")?;
                        }
                    }
                    Some(Ok(Message::Ping(x))) => {
                        stream.send(Message::Pong(x)).await.e2s("cannot send pong")?;
                    }
                    Some(Ok(Message::Pong(_))) => {
                        if !ping_sent {
                            return Err("received pong without a previous ping".into());
                        }
                        ping_sent = false;
                    }
                    Some(Ok(Message::Close(_))) => return Ok(()),
                    Some(x) => {
                        return Err(TunError::Other(format!("unexpected client message: {:?}", x)));
                    }
                    None => return Ok(())
                }
            }
            msg = tun_fut => {
                match msg {
                    Some(msg) => {
                        stream.send(Message::Binary(msg)).await.e2s("cannot send data to client")?;
                    }
                    None => return Ok(())
                }
            }
            _ = timeout_fut => {
                if ping_sent {
                    return Err("timeout".into());
                } else {
                    stream.send(Message::Ping(vec![])).await.e2s("cannot send ping")?;
                    ping_sent = true;
                }
            }
        }
    }
}

async fn tun_handler(server: &'static Server, dev: DeviceAsync, mut w_rx: Receiver<Vec<u8>>) {
    let mut stream = dev.into_framed();
    loop {
        let r_fut = stream.next();
        let w_fut = w_rx.recv();
        tokio::select! {
            frame = r_fut => {
                match frame {
                    Some(Ok(x)) => {
                        let bytes = x.get_bytes();
                        if !server.take_traffic_allowance(bytes.len() as u64).await {
                            continue;
                        }
                        let dst = match extract_dstaddr(bytes) {
                            Ok(x) => x,
                            Err(e) => {
                                println!("invalid packet: {:?}", e);
                                continue;
                            }
                        };
                        let session = server.sessions.read().await.get(&dst).cloned();
                        match session {
                            Some(mut x) => {
                                // Race possible here: take out a session -> session dropped -> try to use the session
                                // When this happens send() will return an error and we can silently ignore it.
                                // Also, drop the packet if not deliverable to avoid blocking on the client side.
                                drop(x.try_send(bytes.to_vec()));
                            }
                            None => {}
                        }
                    }
                    Some(Err(e)) =>{
                        panic!("error: cannot read from tun device: {:?}", e);
                    }
                    None => {
                        panic!("error: EOF from tun device");
                    }
                }
            }
            data = w_fut => {
                let data = data.expect("error: all senders to TUN are dropped");
                let data_len = data.len();
                if !server.take_traffic_allowance(data_len as u64).await {
                    continue;
                }
                match stream.send(TunPacket::new(data)).await {
                    Ok(()) => {}
                    Err(e) => {
                        println!("warning: cannot write a frame of length {} to tun device: {:?}", data_len, e);
                    }
                }
            }
        }
    }
}

fn extract_dstaddr(pkt: &[u8]) -> Result<IpAddr, TunError> {
    if pkt.len() == 0 {
        return Err("empty packet".into());
    }
    Ok(match pkt[0] >> 4 {
        4 => {
            let header = Ipv4HeaderSlice::from_slice(pkt).e2s("invalid ipv4 header")?;
            IpAddr::V4(header.destination_addr())
        }
        6 => {
            let header = Ipv6HeaderSlice::from_slice(pkt).e2s("invalid ipv6 header")?;
            IpAddr::V6(header.destination_addr())
        }
        _ => return Err("invalid protocol type".into()),
    })
}

fn extract_srcaddr(pkt: &[u8]) -> Result<IpAddr, TunError> {
    if pkt.len() == 0 {
        return Err("empty packet".into());
    }
    Ok(match pkt[0] >> 4 {
        4 => {
            let header = Ipv4HeaderSlice::from_slice(pkt).e2s("invalid ipv4 header")?;
            IpAddr::V4(header.source_addr())
        }
        6 => {
            let header = Ipv6HeaderSlice::from_slice(pkt).e2s("invalid ipv6 header")?;
            IpAddr::V6(header.source_addr())
        }
        _ => return Err("invalid protocol type".into()),
    })
}

fn now() -> chrono::DateTime<chrono::Local> {
    chrono::Local::now()
}
