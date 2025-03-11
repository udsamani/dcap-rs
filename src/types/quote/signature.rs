use anyhow::{anyhow, bail, Context};
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};
use x509_cert::certificate::CertificateInner;
use zerocopy::little_endian;

use crate::{
    types::{quote::QuoteCertData, report::EnclaveReportBody, sgx_x509::SgxPckExtension},
    utils,
};

/// Signature data for SGX Quotes
///
/// In the intel docs, this is A 4.4: "ECDSA 2560bit Quote Signature Data Structure"
///
/// This can be used to validate that the quoting enclave itself is valid, and then that
/// the quoting enclave has signed the ISV enclave report.
#[derive(Debug)]
pub struct QuoteSignatureData {
    /// Signature of the report header + report by the attestation key.
    pub isv_signature: Signature,

    /// The public key used to generate the isv_signature.
    pub attestation_pub_key: [u8; 64],

    /// Report of the quoting enclave.
    pub qe_report_body: EnclaveReportBody,

    /// Signature of the quoting enclave report using the PCK cert key.
    pub qe_report_signature: Signature,

    /// Auth data for the quote
    pub auth_data: Vec<u8>,

    /// PCK cert chain for the quote
    pub pck_cert_chain: Vec<CertificateInner>,

    /// PCK extension for the quote
    pub pck_extension: SgxPckExtension,
}

impl QuoteSignatureData {
    pub fn read(bytes: &mut &[u8], version: u16) -> anyhow::Result<Self> {
        let signature_len = utils::read_from_bytes::<little_endian::U32>(bytes)
            .ok_or_else(|| anyhow!("underflow reading signature length"))?
            .get();

        if bytes.len() < signature_len as usize {
            return Err(anyhow!("underflow reading signature"));
        }

        match version {
            3 => Self::read_v3_signature(bytes),
            4 => Self::read_v4_signature(bytes),
            _ => Err(anyhow!("unsupported quote version")),
        }
    }

    fn read_v3_signature(bytes: &mut &[u8]) -> anyhow::Result<Self> {
        let signature_header: EcdsaSignatureHeader = utils::read_from_bytes(bytes)
            .ok_or_else(|| anyhow!("underflow reading signature header"))?;

        let qe_report_body =
            utils::read_array::<{ std::mem::size_of::<EnclaveReportBody>() }>(bytes);
        let qe_report_body = EnclaveReportBody::try_from(qe_report_body)?;

        let qe_report_signature = utils::read_array::<64>(bytes);
        let qe_report_signature =
            Signature::from_slice(&qe_report_signature).context("QE Report Signature")?;

        let cert_data = QuoteCertData::read(bytes)?;

        let pck_cert_chain_data = cert_data.as_pck_cert_chain_data()?;
        let isv_signature = Signature::from_slice(&signature_header.isv_signature)?;

        Ok(QuoteSignatureData {
            isv_signature,
            attestation_pub_key: signature_header.attestation_pub_key,
            qe_report_body,
            qe_report_signature,
            auth_data: pck_cert_chain_data.qe_auth_data.to_vec(),
            pck_cert_chain: pck_cert_chain_data.pck_cert_chain,
            pck_extension: pck_cert_chain_data.pck_extension,
        })
    }

    fn read_v4_signature(bytes: &mut &[u8]) -> anyhow::Result<Self> {
        let signature_header: EcdsaSignatureHeader = utils::read_from_bytes(bytes)
            .ok_or_else(|| anyhow!("underflow reading signature header"))?;

        let cert_data = QuoteCertData::read(bytes)?;
        let quoting_enclave_report_cert_data = cert_data.as_quoting_enclave_report_cert_data()?;

        Ok(QuoteSignatureData {
            isv_signature: Signature::from_slice(&signature_header.isv_signature)?,
            attestation_pub_key: signature_header.attestation_pub_key,
            qe_report_body: quoting_enclave_report_cert_data.qe_report,
            qe_report_signature: quoting_enclave_report_cert_data.qe_report_signature,
            auth_data: quoting_enclave_report_cert_data.qe_auth_data.to_vec(),
            pck_cert_chain: quoting_enclave_report_cert_data.pck_cert_chain,
            pck_extension: quoting_enclave_report_cert_data.pck_extension,
        })
    }

    /// Verfiy the report generated by the quoting enclave.
    ///
    /// By specification, the quoting enclave report data `sgx_report_data_bytes` must b e
    /// SHA256(ECDSA Attestation Key || QE Authentication Data) || 32- 0x00s
    pub fn verify_qe_report(&self) -> anyhow::Result<()> {
        let mut hasher = Sha256::new();

        hasher.update(&self.attestation_pub_key[..]);
        hasher.update(&self.auth_data);
        let digest = hasher.finalize();
        assert_eq!(digest.len(), 32);

        if *digest != self.qe_report_body.user_report_data[..digest.len()] {
            bail!("Quoting enclave report should be hash of attestation key and auth data");
        }

        if self.qe_report_body.user_report_data[digest.len()..] != [0; 32] {
            bail!("Quoting enclave report should be 32 zero bytes padded");
        }

        Ok(())
    }
}

#[derive(Debug, zerocopy::FromBytes, zerocopy::FromZeroes)]
pub struct EcdsaSignatureHeader {
    pub isv_signature: [u8; 64],
    pub attestation_pub_key: [u8; 64],
}
