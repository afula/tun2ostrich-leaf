use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use protobuf::Message;

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::NatManager;
use crate::proxy;
use crate::proxy::AnyInboundHandler;
use crate::Runner;
use crate::{config, option};

#[cfg(feature = "inbound-amux")]
use crate::proxy::amux;
#[cfg(feature = "inbound-http")]
use crate::proxy::http;
#[cfg(feature = "inbound-quic")]
use crate::proxy::quic;
#[cfg(feature = "inbound-shadowsocks")]
use crate::proxy::shadowsocks;
#[cfg(feature = "inbound-socks")]
use crate::proxy::socks;
#[cfg(feature = "inbound-tls")]
use crate::proxy::tls;
#[cfg(feature = "inbound-trojan")]
use crate::proxy::trojan;
#[cfg(feature = "inbound-ws")]
use crate::proxy::ws;

#[cfg(feature = "inbound-chain")]
use crate::proxy::chain;

use super::network_listener::NetworkInboundListener;

#[cfg(feature = "inbound-cat")]
use super::cat_listener::CatInboundListener;

#[cfg(all(
    feature = "inbound-tun",
    any(
        target_os = "ios",
        target_os = "android",
        target_os = "macos",
        target_os = "linux"
    )
))]
use super::tun_listener::TunInboundListener;

pub struct InboundManager {
    network_listeners: HashMap<String, NetworkInboundListener>,
    #[cfg(all(
        feature = "inbound-tun",
        any(
            target_os = "ios",
            target_os = "android",
            target_os = "macos",
            target_os = "linux"
        )
    ))]
    tun_listener: Option<TunInboundListener>,
    #[cfg(feature = "inbound-cat")]
    cat_listener: Option<CatInboundListener>,
    tun_auto: bool,
}

impl InboundManager {
    pub fn new(
        inbounds: &Vec<config::Inbound>,
        dispatcher: Arc<Dispatcher>,
        nat_manager: Arc<NatManager>,
        #[cfg(target_os = "windows")] mut ipset: Vec<String>,
        #[cfg(target_os = "windows")] wintun_path: String,
        #[cfg(target_os = "windows")]
        tun2socks_path: String,
    ) -> Result<Self> {
        let mut handlers: HashMap<String, AnyInboundHandler> = HashMap::new();

        for inbound in inbounds.iter() {
            let tag = String::from(&inbound.tag);
            match inbound.protocol.as_str() {
                #[cfg(feature = "inbound-socks")]
                "socks" => {
                    let stream = Arc::new(socks::inbound::StreamHandler);
                    let datagram = Arc::new(socks::inbound::DatagramHandler);
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        Some(datagram),
                    ));
                    handlers.insert(tag.clone(), handler);
                    #[cfg(all(feature = "inbound-tun", any(target_os = "windows")))]
                    {
                        use crate::common::cmd;
                        use std::process::Command;
                        use tokio::sync::mpsc;
                        let (tun_tx, mut tun_rx) = mpsc::channel(1);
                        let tun2socks_path = tun2socks_path.clone();
                        let ipset = ipset.clone();

                        tokio::spawn(async move {
                            println!("tun2socks path: {}", tun2socks_path.as_str());
                            let _ = Command::new(tun2socks_path.as_str())
                                .arg("-device")
                                .arg("tun://utun233")
                                .arg("-proxy")
                                .arg("socks5://127.0.0.1:1086")
                                // flag.StringVar(&key.LogLevel, "loglevel", "info", "Log level [debug|info|warning|error|silent]")
                                .arg("-loglevel")
                                .arg("info")
                                .spawn()
                                .expect("failed to execute process");
                            println!("init tun device process finished");
                            if let Err(e) = tun_tx.send(()).await {
                                log::warn!("tun device completed signal failed: {}", e);
                            }
                        });

                        tokio::spawn(async move {
                            let _ = tun_rx.recv().await;
                            'netif: loop {
                                use local_ip_address::list_afinet_netifas;
                                std::thread::sleep(std::time::Duration::from_millis(500));
                                let network_interfaces = list_afinet_netifas().unwrap();

                                for (name, _g) in network_interfaces.iter() {
                                    if name == "utun233" {
                                        println!("tun device up");
                                        break 'netif;
                                    }
                                }
                            }
                            // std::thread::sleep(std::time::Duration::from_secs(2));

                            let gateway = cmd::get_default_ipv4_gateway().unwrap();
                            println!("gateway: {:?}", gateway);

                            let out = Command::new("netsh")
                                .arg("interface")
                                .arg("ip")
                                .arg("set")
                                .arg("address")
                                .arg("utun233")
                                .arg("static")
                                .arg("172.7.0.2")
                                .arg("255.255.255.0")
                                .arg("172.7.0.1")
                                .arg("3")
                                .status()
                                .expect("failed to execute command");

                            // netsh interface ip set dns name=%tun_device% static 8.8.8.8
                            let out = Command::new("netsh")
                                .arg("interface")
                                .arg("ip")
                                .arg("set")
                                .arg("dns")
                                .arg("name=utun233")
                                .arg("static")
                                .arg("127.0.0.1")
                                .status()
                                .expect("failed to execute command");
                            println!("process finished with: {}", out);
                            for ip in &ipset {
                                let out = Command::new("route")
                                    .arg("add")
                                    .arg(ip)
                                    .arg(&gateway)
                                    .arg("metric")
                                    .arg("3")
                                    .status()
                                    .expect("failed to execute command");
                                println!("process finished with: {}", out);
                            }
                        });
                    }
                    #[cfg(all(
                        feature = "inbound-tun",
                        any(
                            target_os = "ios",
                            target_os = "android",
                            target_os = "macos",
                            target_os = "linux"
                        )
                    ))]
                    {
                        use crate::common::cmd;
                        use std::process::Command;
                        use tokio::sync::mpsc;
                        let (tun_tx, mut tun_rx) = std::sync::mpsc::channel();
                        let tun2socks_path = tun2socks_path.clone();
                        #[cfg(all(feature = "inbound-tun", any(target_os = "linux",)))]
                        {
                            // ip tuntap del mode tun dev utun233
                            let _ = Command::new("ip")
                                .arg("tuntap")
                                .arg("del")
                                .arg("mode")
                                .arg("tun")
                                // flag.StringVar(&key.LogLevel, "loglevel", "info", "Log level [debug|info|warning|error|silent]")
                                .arg("dev")
                                .arg("utun233")
                                .status()
                                .expect("failed to execute process");
                            // ip tuntap add mode tun dev utun233
                            let _ = Command::new("ip")
                                .arg("tuntap")
                                .arg("add")
                                .arg("mode")
                                .arg("tun")
                                // flag.StringVar(&key.LogLevel, "loglevel", "info", "Log level [debug|info|warning|error|silent]")
                                .arg("dev")
                                .arg("utun233")
                                .status()
                                .expect("failed to execute process");
                            // ip addr add 172.7.0.2 dev utun233
                            let _ = Command::new("ip")
                                .arg("addr")
                                .arg("add")
                                .arg(&*option::DEFAULT_TUN_IPV4_ADDR)
                                // flag.StringVar(&key.LogLevel, "loglevel", "info", "Log level [debug|info|warning|error|silent]")
                                .arg("dev")
                                .arg("utun233")
                                .status()
                                .expect("failed to execute process");
                            // ip link set dev utun233 up
                            let _ = Command::new("ip")
                                .arg("link")
                                .arg("set")
                                // flag.StringVar(&key.LogLevel, "loglevel", "info", "Log level [debug|info|warning|error|silent]")
                                .arg("dev")
                                .arg("utun233")
                                .arg("up")
                                .status()
                                .expect("failed to execute process");
                            std::thread::sleep(std::time::Duration::from_secs(3));
                            log::warn!("tun device is up");
                        }

                        std::thread::spawn(move || {
                            let _ = Command::new(tun2socks_path.as_str())
                                .arg("-device")
                                .arg("tun://utun233")
                                .arg("-proxy")
                                .arg("socks5://127.0.0.1:1086")
                                // flag.StringVar(&key.LogLevel, "loglevel", "info", "Log level [debug|info|warning|error|silent]")
                                .arg("-loglevel")
                                .arg("debug")
                                .spawn()
                                .expect("failed to execute process");
                            println!("init tun device process finished");
                            if let Err(e) = tun_tx.send(()) {
                                log::warn!("tun device completed signal failed: {}", e);
                            }
                        });
                        let _ = tun_rx.recv().unwrap();
                        #[cfg(all(feature = "inbound-tun", any(target_os = "macos",)))]
                        {
                            // ifconfig utun233 172.7.0.2 172.7.0.2 up
                            let _ = Command::new("ifconfig")
                                .arg("utun233")
                                .arg("172.7.0.2")
                                .arg("172.7.0.2")
                                .arg("up")
                                // flag.StringVar(&key.LogLevel, "loglevel", "info", "Log level [debug|info|warning|error|silent]")
                                .status()
                                .expect("failed to execute process");
                        }
                        'netif: loop {
                            use local_ip_address::list_afinet_netifas;
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            let network_interfaces = list_afinet_netifas().unwrap();

                            for (name, _g) in network_interfaces.iter() {
                                if name == "utun233" {
                                    println!("tun device up");
                                    break 'netif;
                                }
                            }
                        }
                    }
                }
                #[cfg(feature = "inbound-http")]
                "http" => {
                    let stream = Arc::new(http::inbound::StreamHandler);
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        None,
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-shadowsocks")]
                "shadowsocks" => {
                    let settings =
                        config::ShadowsocksInboundSettings::parse_from_bytes(&inbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] inbound settings: {}", &tag, e))?;
                    let stream = Arc::new(shadowsocks::inbound::StreamHandler {
                        cipher: settings.method.clone(),
                        password: settings.password.clone(),
                    });
                    let datagram = Arc::new(shadowsocks::inbound::DatagramHandler {
                        cipher: settings.method.clone(),
                        password: settings.password.clone(),
                    });
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        Some(datagram),
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-trojan")]
                "trojan" => {
                    let settings =
                        config::TrojanInboundSettings::parse_from_bytes(&inbound.settings)?;
                    let stream = Arc::new(trojan::inbound::StreamHandler::new(
                        settings.passwords.to_vec(),
                    ));
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        None,
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-ws")]
                "ws" => {
                    let settings =
                        config::WebSocketInboundSettings::parse_from_bytes(&inbound.settings)?;
                    let stream = Arc::new(ws::inbound::StreamHandler::new(settings.path.clone()));
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        None,
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-quic")]
                "quic" => {
                    let settings =
                        config::QuicInboundSettings::parse_from_bytes(&inbound.settings)?;
                    let datagram = Arc::new(quic::inbound::DatagramHandler::new(
                        settings.certificate.clone(),
                        settings.certificate_key.clone(),
                        settings.alpn.clone(),
                    )?);
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        None,
                        Some(datagram),
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-tls")]
                "tls" => {
                    let settings = config::TlsInboundSettings::parse_from_bytes(&inbound.settings)?;
                    let stream = Arc::new(tls::inbound::StreamHandler::new(
                        settings.certificate.clone(),
                        settings.certificate_key.clone(),
                    )?);
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        None,
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                _ => (),
            }
        }

        for _i in 0..4 {
            for inbound in inbounds.iter() {
                let tag = String::from(&inbound.tag);
                #[allow(clippy::single_match)]
                match inbound.protocol.as_str() {
                    #[cfg(feature = "inbound-amux")]
                    "amux" => {
                        let mut actors = Vec::new();
                        let settings =
                            config::AMuxInboundSettings::parse_from_bytes(&inbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] inbound settings: {}", &tag, e)
                                })?;
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        let stream = Arc::new(amux::inbound::StreamHandler {
                            actors: actors.clone(),
                        });
                        let handler = Arc::new(proxy::inbound::Handler::new(
                            tag.clone(),
                            Some(stream),
                            None,
                        ));
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "inbound-chain")]
                    "chain" => {
                        let settings =
                            config::ChainInboundSettings::parse_from_bytes(&inbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] inbound settings: {}", &tag, e)
                                })?;
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let stream = if actors[0].stream().is_ok() {
                            let h = Arc::new(chain::inbound::StreamHandler {
                                actors: actors.clone(),
                            });
                            Some(h as crate::proxy::AnyInboundStreamHandler)
                        } else {
                            None
                        };
                        let datagram = if actors[0].datagram().is_ok() {
                            let h = Arc::new(chain::inbound::DatagramHandler { actors });
                            Some(h as crate::proxy::AnyInboundDatagramHandler)
                        } else {
                            None
                        };
                        let handler =
                            Arc::new(proxy::inbound::Handler::new(tag.clone(), stream, datagram));
                        handlers.insert(tag.clone(), handler);
                    }
                    _ => (),
                }
            }
        }

        let mut network_listeners: HashMap<String, NetworkInboundListener> = HashMap::new();

        #[cfg(all(
            feature = "inbound-tun",
            any(
                target_os = "ios",
                target_os = "android",
                target_os = "macos",
                target_os = "linux"
            )
        ))]
        let mut tun_listener: Option<TunInboundListener> = None;

        #[cfg(feature = "inbound-cat")]
        let mut cat_listener: Option<CatInboundListener> = None;

        let mut tun_auto = false;

        for inbound in inbounds.iter() {
            let tag = String::from(&inbound.tag);
            match inbound.protocol.as_str() {
                #[cfg(all(
                    feature = "inbound-tun",
                    any(
                        target_os = "ios",
                        target_os = "android",
                        target_os = "macos",
                        target_os = "linux"
                    )
                ))]
                "tun" => {
                    let listener = TunInboundListener {
                        inbound: inbound.clone(),
                        dispatcher: dispatcher.clone(),
                        nat_manager: nat_manager.clone(),
                    };
                    tun_listener.replace(listener);
                    let settings =
                        crate::config::TunInboundSettings::parse_from_bytes(&inbound.settings)?;
                    tun_auto = settings.auto;
                }
                #[cfg(feature = "inbound-cat")]
                "cat" => {
                    let listener = CatInboundListener {
                        inbound: inbound.clone(),
                        dispatcher: dispatcher.clone(),
                        nat_manager: nat_manager.clone(),
                    };
                    cat_listener.replace(listener);
                }
                _ => {
                    if inbound.port != 0 {
                        if let Some(h) = handlers.get(&tag) {
                            let listener = NetworkInboundListener {
                                address: inbound.address.clone(),
                                port: inbound.port as u16,
                                handler: h.clone(),
                                dispatcher: dispatcher.clone(),
                                nat_manager: nat_manager.clone(),
                            };
                            network_listeners.insert(tag.clone(), listener);
                        }
                    }
                }
            }
        }

        Ok(InboundManager {
            network_listeners,
            #[cfg(all(
                feature = "inbound-tun",
                any(
                    target_os = "ios",
                    target_os = "android",
                    target_os = "macos",
                    target_os = "linux"
                )
            ))]
            tun_listener,
            #[cfg(feature = "inbound-cat")]
            cat_listener,
            tun_auto,
        })
    }

    pub fn get_network_runners(&self) -> Result<Vec<Runner>> {
        let mut runners: Vec<Runner> = Vec::new();
        for (_, listener) in self.network_listeners.iter() {
            runners.append(&mut listener.listen()?);
        }
        Ok(runners)
    }

    #[cfg(all(
        feature = "inbound-tun",
        any(
            target_os = "ios",
            target_os = "android",
            target_os = "macos",
            target_os = "linux"
        )
    ))]
    pub fn get_tun_runner(&self) -> Result<Runner> {
        if let Some(listener) = &self.tun_listener {
            return listener.listen();
        }
        Err(anyhow!("no tun inbound"))
    }

    #[cfg(feature = "inbound-cat")]
    pub fn get_cat_runner(&self) -> Result<Runner> {
        if let Some(listener) = &self.cat_listener {
            return listener.listen();
        }
        Err(anyhow!("no cat inbound"))
    }

    #[cfg(all(
        feature = "inbound-tun",
        any(
            target_os = "ios",
            target_os = "android",
            target_os = "macos",
            target_os = "linux"
        )
    ))]
    pub fn has_tun_listener(&self) -> bool {
        self.tun_listener.is_some()
    }

    pub fn tun_auto(&self) -> bool {
        self.tun_auto
    }
}
