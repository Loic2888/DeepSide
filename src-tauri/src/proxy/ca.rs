use rcgen::{Certificate, CertificateParams, DistinguishedName};
use std::path::Path;

pub struct CaManager {
    pub root_cert: Certificate,
}

impl CaManager {
    pub fn new(_storage_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        // Always generate FRESH Root CA in memory for now (simplifies persistence issues)
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "DeepSide Root CA");
        dn.push(rcgen::DnType::OrganizationName, "DeepDive Security");
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        
        let root_cert = Certificate::from_params(params)?;
        
        Ok(CaManager {
            root_cert,
        })
    }

    pub fn generate_cert(&self, domain: &str) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, domain);
        params.distinguished_name = dn;

        // Create the leaf certificate
        let leaf_cert = Certificate::from_params(params)?;
        
        // Sign it with the root CA
        // rcgen 0.11: serialize_der_with_signer(&Certificate)
        let cert_der = leaf_cert.serialize_der_with_signer(&self.root_cert)?;
        let key_der = leaf_cert.serialize_private_key_der();

        Ok((cert_der, key_der))
    }
}
