use std::{collections::{BTreeMap, BTreeSet}, time::SystemTime};

use anyhow::bail;
use x509_verify::VerifyingKey;
use x509_cert::{certificate::CertificateInner, crl::CertificateList};

use crate::utils::Expireable;

/// TrustStore is a specialized PKI (Public Key Infrastructure) implementation designed for SGX
/// attestation verification. It manages certificate chains, validates signatures, aand enforces
/// revocation checking to establish secure chains of trust from Intel's root certificates to
/// attestation data.
pub struct TrustStore {
    /// Trusted CAs (Certificate Authorities)
    pub trusted: BTreeMap<String, TrustedIdentity>,
    /// Trusted certificate revocation list.
    pub crl: BTreeSet<String>,
    /// Current time for validity checks
    pub current_time: SystemTime,
}

/// Wrapper for pre-parse trusted identity for verification.
pub struct TrustedIdentity {
    pub cert: CertificateInner,
    pub pk: VerifyingKey
}


impl TrustStore {
    /// Creates a new trust store with the given root certificates
    ///
    /// # Parameters
    /// * `current_time` - Time reference for validity checks
    /// * `roots` - Initial set of trusted root certificates
    ///
    /// # Security Considerations
    /// * The provided roots establish the foundation of trust
    /// * Current_time must come from a secure source on production systems
    pub fn new(current_time: SystemTime, trusted_certs: Vec<CertificateInner>) -> anyhow::Result<Self> {
        let mut trusted = BTreeMap::new();

        for cert in trusted_certs {
            let pk = (&cert)
                .try_into()
                .map_err(|e| anyhow::anyhow!("failed to decode key from certificate: {}", e))?;

            trusted.insert(cert.tbs_certificate.subject.to_string(), TrustedIdentity { cert, pk });

        }


        Ok(Self {
            trusted,
            crl: BTreeSet::default(),
            current_time
        })
    }


    /// Push a trusted CRL to an existing trust store.
    ///
    /// # Parameters
    /// * `crl` - The CRL to push to the trust store.
    ///
    /// # Security Considerations
    /// * The CRL must be trusted and signed by the root certificate.
    /// * The CRL must be valid at the current time.
    pub fn push_trusted_crl(&mut self, crl: CertificateList) {
        if let Some(revoked_certs) = crl.tbs_cert_list.revoked_certificates {
            for cert in revoked_certs {
                self.crl.insert(cert.serial_number.to_string());
            }
        }
    }

    /// Verify an untrusted CRL against a trusted or intermediary signer in that store,
    /// and push the new CRL to the store. Does not affect or remove any existing trusted identities
    /// in the store.
    ///
    /// # Parameters
    /// * `crl` - The CRL to push to the trust store.
    pub fn push_unverified_crl(&mut self, crl: CertificateList) -> anyhow::Result<()> {
        let signer = self.find_issuer(crl.tbs_cert_list.issuer.to_string(), None)?;

        signer
            .pk
            .verify_strict(&crl)
            .map_err(|e| anyhow::anyhow!("failed to verify crl signature: {}", e))?;

        self.push_trusted_crl(crl);
        Ok(())
    }


    /// Verify the leaf node in a certificate chain is rooted in the trust store
    /// and does not use any revoked certificates.
    ///
    /// # Parameters
    /// * `chain` - The certificate chain to verify.
    ///
    pub fn verify_chain_leaf(&self, chain: &[CertificateInner]) -> anyhow::Result<TrustedIdentity> {

        // If the chain is empty, it is not valid
        if chain.is_empty() {
            bail!("certificate chain is empty");
        }

        // If the chain is expired, it is not valid
        if !chain.valid_at(self.current_time) {
            bail!("certificate chain is expired");
        }


        // Work through the certificate chain from the root (last) certificate.
        let mut chain = chain.iter().rev().peekable();
        let mut intermediary = BTreeMap::new();

        loop {
            let cert = chain.next().expect("should have returned after leaf");
            let issuer = cert.tbs_certificate.issuer.to_string();
            let subject = cert.tbs_certificate.subject.to_string();

            // Ensure the certificate is not revoked.
            self.check_crls(cert)?;
            let signer = self.find_issuer(issuer, Some(&intermediary))?;

            // Validate issuer signature.
            signer
                .pk
                .verify_strict(cert)
                .map_err(|e| anyhow::anyhow!("failed to verify issuer signature: {}", e))?;


            let pk = (cert)
                .try_into()
                .map_err(|e| anyhow::anyhow!("failed to decode key from certificate: {}", e))?;

            let identity = TrustedIdentity { cert: cert.clone(), pk };

            if chain.peek().is_none() {
                // If we are at the leaf node of the chain, discard intermediary identities.
                // and return the verified identity.
                intermediary.clear();
                return Ok(identity);
            } else {
                // Otherwise, add the identity to the intermediary store.
                intermediary.insert(subject, identity);
            }
        }

    }

    /// Check the current crls to ensure a certificate is not revoked
    fn check_crls(&self, cert: &CertificateInner) -> anyhow::Result<()> {
        if self
            .crl
            .contains(&cert.tbs_certificate.serial_number.to_string())
        {
            bail!("certificate is revoked");
        }

        Ok(())
    }

    /// Find an issuer in the trusted or intermediary stores
    fn find_issuer<'a>(
        &'a self,
        issuer: String,
        intermediary: Option<&'a BTreeMap<String, TrustedIdentity>>,
    ) -> anyhow::Result<&'a TrustedIdentity> {
        if let Some(signer) = self.trusted.get(&issuer) {
            return Ok(signer);
        }
        if let Some(intermediary) = intermediary {
            if let Some(signer) = intermediary.get(&issuer) {
                return Ok(signer);
            }
        }
        bail!("failed to find trusted issuer")
    }

}
