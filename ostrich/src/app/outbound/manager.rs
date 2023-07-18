use std::{
    convert::From,
};
use indexmap::{map::Values,IndexMap};
use anyhow::{anyhow, Result};
use futures::future::AbortHandle;
use log::*;
use protobuf::Message;

#[cfg(feature = "outbound-direct")]
use crate::proxy::direct;

#[cfg(feature = "outbound-trojan")]
use crate::proxy::trojan;


use crate::proxy::trojan::outbound::tls::make_config;
use crate::{
    app::SyncDnsClient,
    config::{self, Outbound},
    proxy::{outbound::HandlerBuilder, *},
};


pub struct OutboundManager {
    handlers: IndexMap<String, AnyOutboundHandler>,
    #[cfg(feature = "plugin")]
    external_handlers: super::plugin::ExternalHandlers,
    default_handler: Option<String>,
    abort_handles: Vec<AbortHandle>,
}

struct HandlerCacheEntry<'a> {
    tag: &'a str,
    handler: AnyOutboundHandler,
    protocol: &'a str,
    settings: &'a Vec<u8>,
}

impl OutboundManager {
    #[allow(clippy::type_complexity)]
    fn load_handlers(
        outbounds: &Vec<Outbound>,
        dns_client: SyncDnsClient,
        handlers: &mut IndexMap<String, AnyOutboundHandler>,
        #[cfg(feature = "plugin")] external_handlers: &mut super::plugin::ExternalHandlers,
        default_handler: &mut Option<String>,
        abort_handles: &mut Vec<AbortHandle>,
    ) -> Result<()> {
        // If there are multiple outbounds with the same setting, we would want
        // a shared one to reduce memory usage. This vector is used as a cache for
        // unseen outbounds so we can reuse them later.
        let mut cached_handlers: Vec<HandlerCacheEntry> = Vec::new();

        'loop1: for outbound in outbounds.iter() {
            let tag = String::from(&outbound.tag);
            if handlers.contains_key(&tag) {
                continue;
            }
            if default_handler.is_none() {
                default_handler.replace(String::from(&outbound.tag));
                debug!("default handler [{}]", &outbound.tag);
            }

            // Check whether an identical one already exist.
            for e in cached_handlers.iter() {
                if e.protocol == &outbound.protocol && e.settings == &outbound.settings {
                    trace!("add handler [{}] cloned from [{}]", &tag, &e.tag);
                    handlers.insert(tag.clone(), e.handler.clone());
                    continue 'loop1;
                }
            }

            let h: AnyOutboundHandler = match outbound.protocol.as_str() {
                #[cfg(feature = "outbound-direct")]
                "direct" => HandlerBuilder::default()
                    .tag(tag.clone())
                    .color(colored::Color::Green)
                    .stream_handler(Box::new(direct::StreamHandler))
                    .datagram_handler(Box::new(direct::DatagramHandler))
                    .build(),
                #[cfg(feature = "outbound-trojan")]
                "trojan" => {
                    let settings =
                        config::TrojanOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let server_name = settings.server_name.clone();

                    let tls_config = make_config(&settings);

                    let tcp = Box::new(trojan::outbound::StreamHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        password: settings.password.clone(),

                        server_name: server_name.clone(),
                        tls_config: tls_config.clone(),
                    });
                    let udp = Box::new(trojan::outbound::DatagramHandler {
                        address: settings.address,
                        port: settings.port as u16,
                        password: settings.password,

                        server_name: server_name.clone(),
                        tls_config: tls_config.clone(),
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .stream_handler(tcp)
                        .datagram_handler(udp)
                        .build()
                }
                _ => continue,
            };
            cached_handlers.push(HandlerCacheEntry {
                tag: &outbound.tag,
                handler: h.clone(),
                protocol: &outbound.protocol,
                settings: &outbound.settings,
            });
            trace!("add handler [{}]", &tag);
            handlers.insert(tag, h);
        }

        drop(cached_handlers);

        Ok(())
    }

    pub fn new(outbounds: &Vec<Outbound>, dns_client: SyncDnsClient) -> Result<Self> {
        let mut handlers: IndexMap<String, AnyOutboundHandler> = IndexMap::new();
        #[cfg(feature = "plugin")]
        let mut external_handlers = super::plugin::ExternalHandlers::new();
        let mut default_handler: Option<String> = None;
        let mut abort_handles: Vec<AbortHandle> = Vec::new();
        for _i in 0..4 {
            Self::load_handlers(
                outbounds,
                dns_client.clone(),
                &mut handlers,
                #[cfg(feature = "plugin")]
                &mut external_handlers,
                &mut default_handler,
                &mut abort_handles,
            )?;
        }
        Ok(OutboundManager {
            handlers,
            #[cfg(feature = "plugin")]
            external_handlers,
            default_handler,
            abort_handles,
        })
    }

    pub fn add(&mut self, tag: String, handler: AnyOutboundHandler) {
        self.handlers.insert(tag, handler);
    }

    pub fn get(&self, tag: &str) -> Option<AnyOutboundHandler> {
        self.handlers.get(tag).map(Clone::clone)
    }

    pub fn default_handler(&self) -> Option<String> {
        self.default_handler.as_ref().map(Clone::clone)
    }

    pub fn handlers(&self) -> Handlers {
        Handlers {
            inner: self.handlers.values(),
        }
    }

}

pub struct Handlers<'a> {
    inner: Values<'a, String, AnyOutboundHandler>,
}

impl<'a> Iterator for Handlers<'a> {
    type Item = &'a AnyOutboundHandler;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}
