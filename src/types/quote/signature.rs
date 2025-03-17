use anyhow::{Context, anyhow, bail};
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};
use x509_cert::certificate::CertificateInner;
use zerocopy::little_endian;

use crate::{
    types::{quote::QuoteCertData, report::EnclaveReportBody, sgx_x509::SgxPckExtension},
    utils::{self, cert_chain_processor},
};

use super::CertificationKeyType;

/// Signature data for SGX Quotes
///
/// In the intel docs, this is A 4.4: "ECDSA 2560bit Quote Signature Data Structure"
///
/// This can be used to validate that the quoting enclave itself is valid, and then that
/// the quoting enclave has signed the ISV enclave report.
#[derive(Debug)]
pub struct QuoteSignatureData<'a> {
    /// Signature of the report header + report by the attestation key.
    pub isv_signature: Signature,

    /// The public key used to generate the isv_signature.
    pub attestation_pub_key: [u8; 64],

    /// Report of the quoting enclave.
    pub qe_report_body: EnclaveReportBody,

    /// Signature of the quoting enclave report using the PCK cert key.
    pub qe_report_signature: Signature,

    /// Auth data for the quote
    pub auth_data: &'a [u8],

    /// PCK cert chain for the quote
    pub pck_cert_chain: Vec<CertificateInner>,

    /// PCK extension for the quote
    pub pck_extension: SgxPckExtension,
}

impl<'a> QuoteSignatureData<'a> {
    pub fn read(bytes: &mut &'a [u8], version: u16) -> anyhow::Result<Self> {
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

    fn read_v3_signature(bytes: &mut &'a [u8]) -> anyhow::Result<Self> {
        let signature_header: EcdsaSignatureHeader = utils::read_from_bytes(bytes)
            .ok_or_else(|| anyhow!("underflow reading signature header"))?;

        let qe_report_body =
            utils::read_array::<{ std::mem::size_of::<EnclaveReportBody>() }>(bytes);
        let qe_report_body = EnclaveReportBody::try_from(qe_report_body)?;

        let qe_report_signature = utils::read_bytes(bytes, 64);
        let qe_report_signature =
            Signature::from_slice(qe_report_signature).context("QE Report Signature")?;

        let auth_data_size = utils::read_from_bytes::<little_endian::U16>(bytes)
            .ok_or_else(|| anyhow!("Failed to read auth data size"))?
            .get();

        if bytes.len() < auth_data_size as usize {
            return Err(anyhow!("buffer underflow"));
        }

        let auth_data = utils::read_bytes(bytes, auth_data_size as usize);
        let cert_data = QuoteCertData::read(bytes)?;

        let pck_cert_chain_data = cert_data.as_pck_cert_chain_data()?;
        let isv_signature = Signature::from_slice(&signature_header.isv_signature)?;

        Ok(QuoteSignatureData {
            isv_signature,
            attestation_pub_key: signature_header.attestation_pub_key,
            qe_report_body,
            qe_report_signature,
            auth_data,
            pck_cert_chain: pck_cert_chain_data.pck_cert_chain,
            pck_extension: pck_cert_chain_data.pck_extension,
        })
    }

    fn read_v4_signature(bytes: &mut &'a [u8]) -> anyhow::Result<Self> {
        let signature_header: EcdsaSignatureHeader = utils::read_from_bytes(bytes)
            .ok_or_else(|| anyhow!("underflow reading signature header"))?;

        let cert_data_struct = QuoteCertData::read(bytes)?;

        if cert_data_struct.cert_key_type.get() != CertificationKeyType::EcdsaSigAuxData as u16 {
            return Err(anyhow!(
                "cannot transform cert data into quoting enclave report cert data"
            ));
        }

        // Create a mutable reference to parse the cert_data
        let mut data = cert_data_struct.cert_data;

        // Parse the QE report
        let qe_report_bytes =
            utils::read_array::<{ std::mem::size_of::<EnclaveReportBody>() }>(&mut data);

        let qe_report_body =
            EnclaveReportBody::try_from(qe_report_bytes).context("Failed to parse QE report")?;

        // Parse the QE report signature
        let qe_report_sig_bytes = utils::read_bytes(&mut data, 64);
        let qe_report_signature = Signature::from_slice(qe_report_sig_bytes)
            .context("Failed to parse QE report signature")?;

        // Read auth data size and auth data
        let auth_data_size = utils::read_from_bytes::<little_endian::U16>(&mut data)
            .ok_or_else(|| anyhow!("Failed to read auth data size"))?;

        if data.len() < auth_data_size.get() as usize {
            return Err(anyhow!("buffer underflow"));
        }

        let qe_auth_data = utils::read_bytes(&mut data, auth_data_size.get() as usize);

        let cert_key_type = utils::read_from_bytes::<little_endian::U16>(&mut data)
            .ok_or_else(|| anyhow!("incorrect buffer size"))?;

        if cert_key_type.get() != CertificationKeyType::PckCertChain as u16 {
            return Err(anyhow!(
                "cannot transform cert data into pck cert chain data"
            ));
        }

        let cert_data_size = utils::read_from_bytes::<little_endian::U32>(&mut data)
            .ok_or_else(|| anyhow!("incorrect buffer size"))?
            .get();

        let cert_data = utils::read_bytes(&mut data, cert_data_size as usize);
        let cert_data = cert_data.strip_suffix(&[0]).unwrap_or(cert_data);

        let pck_cert_chain = cert_chain_processor::load_pem_chain_bpf_friendly(cert_data)
            .context("Failed to parse PCK certificate chain")?;

        let pck_extension = pck_cert_chain
            .first()
            .context("CertChain")?
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|extensions| {
                extensions
                    .iter()
                    .find(|ext| SgxPckExtension::is_pck_ext(ext.extn_id.to_string()))
            })
            .ok_or_else(|| anyhow!("PCK Certificate does not contain a SGX Extension"))?;

        let pck_extension = SgxPckExtension::from_der(pck_extension.extn_value.as_bytes())
            .context("PCK Extension")?;

        Ok(QuoteSignatureData {
            isv_signature: Signature::from_slice(&signature_header.isv_signature)?,
            attestation_pub_key: signature_header.attestation_pub_key,
            qe_report_body,
            qe_report_signature,
            auth_data: qe_auth_data,
            pck_cert_chain,
            pck_extension,
        })
    }

    /// Verfiy the report generated by the quoting enclave.
    ///
    /// By specification, the quoting enclave report data `sgx_report_data_bytes` must b e
    /// SHA256(ECDSA Attestation Key || QE Authentication Data) || 32- 0x00s
    pub fn verify_qe_report(&self) -> anyhow::Result<()> {
        let mut hasher = Sha256::new();

        hasher.update(&self.attestation_pub_key[..]);
        hasher.update(self.auth_data);
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
