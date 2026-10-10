use anchor_sdk::{
    Capability, PairingSession, Session, SessionEvent, SessionIdentity, notifications, pairing,
    quinn_transport, v1,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use quinn::Endpoint;
use rcgen::{CertificateParams, KeyPair};
use rustls::{RootCertStore, pki_types::CertificateDer};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::{
    env, fs, io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Deserialize)]
struct ProbeResponse {
    device_id: String,
    device_name: String,
    port: u16,
    certificate: String,
}

pub struct DiscoveredDesktop {
    pub device_id: String,
    pub device_name: String,
    pub address: SocketAddr,
    pub certificate_der: Vec<u8>,
}

pub struct AnchorIdentity {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub device_id: String,
}

/// A connected Anchor client with the notification capability already open.
pub struct AnchorClient {
    // Quinn closes its connections when the endpoint is dropped.
    _endpoint: Endpoint,
    session: Session,
    notifications: Capability,
}

impl AnchorClient {
    /// Discover Anchor desktop, pair on first use, connect, and subscribe to
    /// its notification records.
    pub async fn connect() -> AnchorResult<Self> {
        // Multiple dependencies enable different Rustls crypto backends, so
        // choose one explicitly instead of letting Rustls panic while guessing.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let identity = load_or_create_identity()?;
        let desktop = tokio::task::spawn_blocking(discover_desktop).await??;

        println!(
            "Found Anchor desktop '{}' at {}",
            desktop.device_name, desktop.address
        );

        ensure_paired(&identity, &desktop).await?;

        let endpoint = create_client_endpoint(&identity, &desktop.certificate_der)?;
        let session = Session::connect(
            &endpoint,
            desktop.address,
            "anchor.local",
            session_identity(&identity),
        )
        .await?;

        let notifications = session
            .open_capability(
                notifications::ENDPOINT_ID,
                notifications::CAPABILITY_NAME,
                notifications::CAPABILITY_MAJOR,
            )
            .await?;

        println!("Listening for Anchor notifications");

        Ok(Self {
            _endpoint: endpoint,
            session,
            notifications,
        })
    }

    /// Wait for and decode the next posted notification. Other Anchor session
    /// traffic is ignored here so the rule engine only sees notifications.
    pub async fn next_notification(&self) -> AnchorResult<notifications::NotificationPosted> {
        loop {
            match self.session.next_event().await? {
                SessionEvent::CapabilityRecord {
                    capability_session_id,
                    type_url,
                    payload,
                } if capability_session_id == self.notifications.session_id()
                    && type_url == notifications::POSTED_TYPE_URL =>
                {
                    return Ok(notifications::decode_posted(&payload)?);
                }
                SessionEvent::CapabilityClosed {
                    capability_session_id,
                    ..
                } if capability_session_id == self.notifications.session_id() => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Anchor closed the notifications capability",
                    )
                    .into());
                }
                SessionEvent::SessionClosed { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Anchor session closed",
                    )
                    .into());
                }
                _ => {}
            }
        }
    }
}

/**
 * Network probing
 */

pub fn discover_desktop() -> AnchorResult<DiscoveredDesktop> {
    println!("Discovering Anchor on UDP port 5028...");
    match discover_desktop_udp() {
        Ok(desktop) => Ok(desktop),
        Err(error)
            if error.downcast_ref::<io::Error>().is_some_and(|error| {
                matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                )
            }) =>
        {
            println!("No UDP discovery reply; trying Anchor's mDNS advertisement...");
            discover_desktop_mdns()
        }
        Err(error) => Err(error),
    }
}

fn discover_desktop_udp() -> AnchorResult<DiscoveredDesktop> {
    const PROBE_REQUEST: &[u8] = b"ANCHOR_PROBE_V1";
    const RESPONSE_PREFIX: &[u8] = b"ANCHOR_HERE_V1\n";

    let socket = UdpSocket::bind("127.0.0.1:0")?;

    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    socket.send_to(PROBE_REQUEST, "127.0.0.1:5028")?;

    let mut buffer = [0_u8; 4096];

    let (length, source) = socket.recv_from(&mut buffer).map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Anchor discovery timed out: no reply from 127.0.0.1:5028 within 2 seconds. \
                 Start Anchor desktop on this machine and check that its UDP discovery responder is running.",
            )
        } else {
            error
        }
    })?;
    let response = &buffer[..length];

    let json = response.strip_prefix(RESPONSE_PREFIX).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Anchor discovery response",
        )
    })?;

    let response: ProbeResponse = serde_json::from_slice(json)?;

    let certificate_der = URL_SAFE_NO_PAD.decode(&response.certificate)?;

    Ok(DiscoveredDesktop {
        device_id: response.device_id,
        device_name: response.device_name,
        address: SocketAddr::new(source.ip(), response.port),
        certificate_der,
    })
}

fn discover_desktop_mdns() -> AnchorResult<DiscoveredDesktop> {
    const SERVICE_TYPE: &str = "_anchor._udp.local.";
    let local_hostname = fs::read_to_string("/etc/hostname").ok();
    let daemon = ServiceDaemon::new()?;
    let result = (|| {
        let receiver = daemon.browse(SERVICE_TYPE)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while let Ok(event) =
            receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            if let ServiceEvent::ServiceResolved(info) = event {
                if let Some(address) = mdns_address(&info, local_hostname.as_deref()) {
                    return desktop_from_mdns(&info, address);
                }
                // A service can resolve after an AAAA record arrives, before
                // its A record. Keep browsing for a usable IPv4 update.
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Anchor discovery failed: no UDP probe reply or mDNS advertisement. \
             Check that Anchor desktop is running and advertising _anchor._udp.local.",
        )
        .into())
    })();
    let _ = daemon.shutdown();
    result
}

fn mdns_address(info: &ServiceInfo, local_hostname: Option<&str>) -> Option<SocketAddr> {
    // Anchor's listener binds 0.0.0.0, so the local desktop is reachable on
    // loopback even when mDNS initially reports only an IPv6 interface address.
    // TLS still verifies the certificate from the advertisement.
    if local_hostname.is_some_and(|hostname| {
        info.get_hostname()
            .eq_ignore_ascii_case(&format!("{}.local.", hostname.trim()))
    }) {
        return Some(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), info.get_port()));
    }

    info.get_addresses_v4()
        .into_iter()
        .copied()
        .min()
        .map(|address| SocketAddr::new(address.into(), info.get_port()))
}

fn desktop_from_mdns(info: &ServiceInfo, address: SocketAddr) -> AnchorResult<DiscoveredDesktop> {
    let device_id = info
        .get_property_val_str("device_id")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_data("Anchor mDNS advertisement is missing device_id"))?;
    let device_name = info
        .get_property_val_str("device_name")
        .unwrap_or(info.get_hostname());

    // Older desktops advertise one certificate property; newer versions split
    // it into numbered chunks to fit the DNS-SD TXT record size limit.
    let encoded_certificate = if let Some(certificate) = info.get_property_val_str("certificate") {
        certificate.to_string()
    } else {
        let mut certificate = String::new();
        for index in 0..info.get_properties().len() {
            match info.get_property_val_str(&format!("certificate{index}")) {
                Some(chunk) => certificate.push_str(chunk),
                None => break,
            }
        }
        certificate
    };
    if encoded_certificate.is_empty() {
        return Err(invalid_data(
            "Anchor mDNS advertisement is missing its public certificate; update Anchor desktop",
        ));
    }
    let certificate_der = URL_SAFE_NO_PAD.decode(encoded_certificate).map_err(|_| {
        invalid_data(
            "Anchor mDNS public certificate is invalid or truncated; update Anchor desktop",
        )
    })?;
    Ok(DiscoveredDesktop {
        device_id: device_id.to_string(),
        device_name: device_name.to_string(),
        address,
        certificate_der,
    })
}

fn create_client_endpoint(
    identity: &AnchorIdentity,
    desktop_certificate_der: &[u8],
) -> AnchorResult<Endpoint> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(desktop_certificate_der.to_vec()))?;

    let mut certificate_reader = identity.certificate_pem.as_bytes();
    let client_certificates =
        rustls_pemfile::certs(&mut certificate_reader).collect::<Result<Vec<_>, _>>()?;

    let mut private_key_reader = identity.private_key_pem.as_bytes();
    let private_key = rustls_pemfile::private_key(&mut private_key_reader)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Flashbang private key is missing",
        )
    })?;

    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certificates, private_key)?;
    let config = quinn_transport::client_config(tls)?;

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

async fn ensure_paired(identity: &AnchorIdentity, desktop: &DiscoveredDesktop) -> AnchorResult<()> {
    if let Some((device_id, certificate)) = load_paired_desktop()? {
        if device_id == desktop.device_id && certificate == desktop.certificate_der {
            return Ok(());
        }
    }

    let endpoint = create_client_endpoint(identity, &desktop.certificate_der)?;
    let node_id: [u8; 32] = Sha256::digest(identity.device_id.trim().as_bytes()).into();
    let client_certificate = certificate_der(identity)?;

    // Bind the approval echoed by the desktop to both certificates and this
    // client identity. The TLS connection is already pinned to discovery.
    let mut transcript = Sha256::new();
    transcript.update(b"flashbang/anchor-pairing/v1");
    transcript.update(&desktop.certificate_der);
    transcript.update(&client_certificate);
    transcript.update(node_id);
    let transcript_hash: [u8; 32] = transcript.finalize().into();

    let pairing = PairingSession::connect(
        &endpoint,
        desktop.address,
        "anchor.local",
        pairing::Hello {
            invitation_id: Vec::new(),
            node_id,
            display_name: "Flashbang".into(),
            device_kind: 1,
            transcript_hash,
        },
    )
    .await?;

    println!("Approve the Flashbang pairing request in Anchor desktop...");

    match pairing.next_resolution().await? {
        v1::control_envelope::Body::PairingApprove(approval) => {
            if approval.transcript_hash != transcript_hash {
                return Err(invalid_data(
                    "Anchor returned a mismatched pairing transcript",
                ));
            }
            if approval.approver_device_id != desktop.device_id
                || approval.approver_certificate_der != desktop.certificate_der
            {
                return Err(invalid_data(
                    "Anchor pairing identity changed during approval",
                ));
            }

            save_paired_desktop(desktop)?;
            pairing.close(0, b"pairing complete");
            println!("Anchor pairing approved");
            Ok(())
        }
        v1::control_envelope::Body::PairingReject(_) => {
            pairing.close(0, b"pairing rejected");
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Anchor pairing was rejected or timed out",
            )
            .into())
        }
        _ => Err(invalid_data("Anchor returned an invalid pairing response")),
    }
}

fn session_identity(identity: &AnchorIdentity) -> SessionIdentity {
    SessionIdentity {
        node_id: Sha256::digest(identity.device_id.trim().as_bytes()).into(),
        display_name: "Flashbang".into(),
        device_kind: 1,
        endpoints: Vec::new(),
    }
}

fn certificate_der(identity: &AnchorIdentity) -> AnchorResult<Vec<u8>> {
    let mut reader = identity.certificate_pem.as_bytes();
    rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()?
        .map(|certificate| certificate.as_ref().to_vec())
        .ok_or_else(|| invalid_data("Flashbang certificate is missing"))
}

fn paired_desktop_paths() -> (PathBuf, PathBuf) {
    let directory = identity_directory();
    (
        directory.join("desktop_device_id"),
        directory.join("desktop_certificate.der"),
    )
}

fn load_paired_desktop() -> io::Result<Option<(String, Vec<u8>)>> {
    let (device_id_path, certificate_path) = paired_desktop_paths();
    if !device_id_path.exists() || !certificate_path.exists() {
        return Ok(None);
    }
    Ok(Some((
        fs::read_to_string(device_id_path)?.trim().to_owned(),
        fs::read(certificate_path)?,
    )))
}

fn save_paired_desktop(desktop: &DiscoveredDesktop) -> io::Result<()> {
    let directory = identity_directory();
    fs::create_dir_all(&directory)?;
    let (device_id_path, certificate_path) = paired_desktop_paths();
    fs::write(device_id_path, &desktop.device_id)?;
    fs::write(certificate_path, &desktop.certificate_der)?;
    Ok(())
}

fn invalid_data(message: &'static str) -> Box<dyn Error + Send + Sync> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

/**
 * Identity related functions
 */
fn identity_directory() -> PathBuf {
    if let Some(config_home) = env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(config_home).join("flashbang");
    }

    let home = env::var_os("HOME").expect("HOME is not set");

    PathBuf::from(home).join(".config").join("flashbang")
}

fn load_identity() -> io::Result<Option<AnchorIdentity>> {
    let directory = identity_directory();

    let certificate_path = directory.join("certificate.pem");
    let private_key_path = directory.join("private_key.pem");
    let device_id_path = directory.join("device_id");

    if !certificate_path.exists() || !private_key_path.exists() || !device_id_path.exists() {
        return Ok(None);
    }

    Ok(Some(AnchorIdentity {
        certificate_pem: fs::read_to_string(certificate_path)?,
        private_key_pem: fs::read_to_string(private_key_path)?,
        device_id: fs::read_to_string(device_id_path)?,
    }))
}

pub type AnchorResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub fn load_or_create_identity() -> AnchorResult<AnchorIdentity> {
    if let Some(identity) = load_identity()? {
        return Ok(identity);
    }

    let directory = identity_directory();
    fs::create_dir_all(&directory)?;

    let key_pair = KeyPair::generate()?;

    let parameters = CertificateParams::new(vec!["flashbang.local".to_string()])?;

    let certificate = parameters.self_signed(&key_pair)?;

    let identity = AnchorIdentity {
        certificate_pem: certificate.pem(),
        private_key_pem: key_pair.serialize_pem(),
        device_id: Uuid::new_v4().to_string(),
    };

    fs::write(directory.join("certificate.pem"), &identity.certificate_pem)?;

    fs::write(directory.join("private_key.pem"), &identity.private_key_pem)?;

    fs::write(directory.join("device_id"), &identity.device_id)?;

    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn advertisement(properties: HashMap<String, String>) -> ServiceInfo {
        ServiceInfo::new(
            "_anchor._udp.local.",
            "test-desktop",
            "test-desktop.local.",
            "127.0.0.1,::1",
            5027,
            properties,
        )
        .unwrap()
    }

    #[test]
    fn reads_legacy_mdns_certificate_and_ipv4_endpoint() {
        let certificate = vec![1, 2, 3, 4];
        let info = advertisement(HashMap::from([
            ("device_id".into(), "test-device".into()),
            ("device_name".into(), "Test Desktop".into()),
            ("certificate".into(), URL_SAFE_NO_PAD.encode(&certificate)),
        ]));

        let desktop = desktop_from_mdns(&info, mdns_address(&info, None).unwrap()).unwrap();
        assert_eq!(desktop.device_id, "test-device");
        assert_eq!(desktop.device_name, "Test Desktop");
        assert_eq!(desktop.address, "127.0.0.1:5027".parse().unwrap());
        assert_eq!(desktop.certificate_der, certificate);
    }

    #[test]
    fn reassembles_numbered_mdns_certificate_chunks() {
        let certificate = vec![42; 700];
        let encoded = URL_SAFE_NO_PAD.encode(&certificate);
        let mut properties = HashMap::from([("device_id".into(), "test-device".into())]);
        for (index, chunk) in encoded.as_bytes().chunks(220).enumerate().rev() {
            properties.insert(
                format!("certificate{index}"),
                String::from_utf8(chunk.to_vec()).unwrap(),
            );
        }

        let info = advertisement(properties);
        let desktop = desktop_from_mdns(&info, mdns_address(&info, None).unwrap()).unwrap();
        assert_eq!(desktop.certificate_der, certificate);
    }

    #[test]
    fn rejects_mdns_advertisement_without_certificate_pin() {
        let info = advertisement(HashMap::from([("device_id".into(), "test-device".into())]));
        let error = desktop_from_mdns(&info, mdns_address(&info, None).unwrap())
            .err()
            .expect("discovery must fail");
        assert!(error.to_string().contains("missing its public certificate"));
    }

    #[test]
    fn local_ipv6_only_advertisement_uses_ipv4_loopback() {
        let info = ServiceInfo::new(
            "_anchor._udp.local.",
            "local-desktop",
            "local-desktop.local.",
            "fe80::1234",
            5027,
            None,
        )
        .unwrap();

        assert_eq!(
            mdns_address(&info, Some("local-desktop\n")),
            Some("127.0.0.1:5027".parse().unwrap())
        );
    }

    #[test]
    fn remote_ipv6_only_advertisement_waits_for_ipv4_update() {
        let ipv6_only = ServiceInfo::new(
            "_anchor._udp.local.",
            "remote-desktop",
            "remote-desktop.local.",
            "fe80::1234",
            5027,
            None,
        )
        .unwrap();
        assert_eq!(mdns_address(&ipv6_only, Some("local-desktop")), None);

        let updated = ServiceInfo::new(
            "_anchor._udp.local.",
            "remote-desktop",
            "remote-desktop.local.",
            "fe80::1234,10.0.0.2",
            5027,
            None,
        )
        .unwrap();
        assert_eq!(
            mdns_address(&updated, Some("local-desktop")),
            Some("10.0.0.2:5027".parse().unwrap())
        );
    }
}
