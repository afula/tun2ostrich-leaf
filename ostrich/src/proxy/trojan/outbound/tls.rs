use crate::config::TrojanOutboundSettings;
use std::sync::Arc;
use tokio_rustls::rustls::OwnedTrustAnchor;
use webpki_roots;

pub fn make_config(config: &TrojanOutboundSettings) -> Arc<tokio_rustls::rustls::ClientConfig> {
    let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();

    root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let tls_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth(); // i guess this was previously the default?
    Arc::new(tls_config)
}
