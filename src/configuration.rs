use std::fs;
use std::path::Path;
use std::sync::Arc;

use rcgen::{
    Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use time::{Duration, OffsetDateTime};

use crate::error::{ProxyError, ResultExt};

const CA_CERT_PATH: &str = "dolos-root-ca.crt.pem";
const CA_KEY_PATH: &str = "dolos-root-ca.key.pem";

pub struct Configuration {
    pub root_ca: RootCa,
    pub client_config: Arc<ClientConfig>,
}

pub struct RootCa {
    issuer: Certificate,
    key: KeyPair,
}

impl Configuration {
    pub fn load() -> Result<Self, ProxyError> {
        let cert_pem = fs::read_to_string(Path::new(CA_CERT_PATH)).context("read CA certificate")?;
        let key_pem = fs::read_to_string(Path::new(CA_KEY_PATH)).context("read CA private key")?;
        let params =
            CertificateParams::from_ca_cert_pem(&cert_pem).context("parse CA certificate")?;
        let key = KeyPair::from_pem(&key_pem).context("parse CA private key")?;
        let issuer = params.self_signed(&key).context("prepare CA issuer")?;

        let client_config = Arc::new(Self::client_config());

        Ok(Self {
            root_ca: RootCa { issuer, key },
            client_config,
        })
    }

    pub fn client_config() -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        client_config
    }

    pub fn server_config(&self, sni: &str) -> Result<Arc<ServerConfig>, ProxyError> {
        let key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate leaf private key")?;

        let mut params = CertificateParams::new(vec![sni.to_owned()])
            .context("create leaf certificate parameters")?;

        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::minutes(5);
        params.not_after = now + Duration::days(1);
        params.distinguished_name.remove(DnType::CommonName);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let cert = params
            .signed_by(&key, &self.root_ca.issuer, &self.root_ca.key)
            .context("sign leaf certificate")?;

        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], private_key)
            .context("configure downstream TLS")?;

        Ok(Arc::new(config))
    }
}
