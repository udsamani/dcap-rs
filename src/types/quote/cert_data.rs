use anyhow::{Context, anyhow};
use p256::ecdsa::Signature;
use x509_cert::certificate::CertificateInner;
use zerocopy::little_endian;

use crate::{
    types::{report::EnclaveReportBody, sgx_x509::SgxPckExtension},
    utils,
};

#[derive(Debug)]
pub struct QuoteCertData<'a> {
    /// Type of cert key
    pub cert_key_type: little_endian::U16,

    /// Size of the cert data
    pub cert_data_size: little_endian::U32,

    /// Cert data
    pub cert_data: &'a [u8],
}

impl<'a> QuoteCertData<'a> {
    pub fn read(bytes: &mut &'a [u8]) -> anyhow::Result<Self> {
        let cert_key_type = utils::read_from_bytes::<little_endian::U16>(bytes)
            .ok_or_else(|| anyhow!("incorrect buffer size"))?;

        let cert_data_size = utils::read_from_bytes::<little_endian::U32>(bytes)
            .ok_or_else(|| anyhow!("incorrect buffer size"))?;

        let cert_data = utils::read_bytes(bytes, cert_data_size.get() as usize);

        Ok(Self {
            cert_key_type,
            cert_data_size,
            cert_data,
        })
    }

    pub fn as_quoting_enclave_report_cert_data(
        &self,
    ) -> anyhow::Result<QuotingEnclaveReportCertData> {
        if self.cert_key_type.get() != CertificationKeyType::EcdsaSigAuxData as u16 {
            return Err(anyhow!(
                "cannot transform cert data into quoting enclave report cert data"
            ));
        }

        // Create a mutable reference to parse the cert_data
        let mut data = self.cert_data;

        // Parse the QE report
        let qe_report_bytes =
            utils::read_array::<{ std::mem::size_of::<EnclaveReportBody>() }>(&mut data);

        let qe_report =
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

        let pck_cert_chain = CertificateInner::load_pem_chain(cert_data)
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

        Ok(QuotingEnclaveReportCertData {
            qe_report,
            qe_report_signature,
            qe_auth_data,
            pck_cert_chain_data: PckCertChainData {
                pck_cert_chain: pck_cert_chain.clone(),
                pck_extension: SgxPckExtension::from_der(pck_extension.extn_value.as_bytes())
                    .context("PCK Extension")?,
            },
        })
    }

    pub fn as_pck_cert_chain_data(&self) -> anyhow::Result<PckCertChainData> {
        if self.cert_key_type.get() != CertificationKeyType::PckCertChain as u16 {
            return Err(anyhow!(
                "cannot transform cert data into pck cert chain data"
            ));
        }

        let cert_data = self.cert_data.strip_suffix(&[0]).unwrap_or(self.cert_data);
        let pck_cert_chain = CertificateInner::load_pem_chain(cert_data)
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

        Ok(PckCertChainData {
            pck_cert_chain: pck_cert_chain.clone(),
            pck_extension: SgxPckExtension::from_der(pck_extension.extn_value.as_bytes())
                .context("PCK Extension")?,
        })
    }
}

pub struct QuotingEnclaveReportCertData<'a> {
    pub qe_report: EnclaveReportBody,

    pub qe_report_signature: Signature,

    pub qe_auth_data: &'a [u8],

    pub pck_cert_chain_data: PckCertChainData,
}

pub struct PckCertChainData {
    pub pck_cert_chain: Vec<CertificateInner>,

    pub pck_extension: SgxPckExtension,
}

#[derive(Debug, PartialEq)]
enum CertificationKeyType {
    _PpidClearText = 1,
    _PpidRsa2048Encrypted,
    _PpidRsa3072Encrypted,
    _PckCleartext,
    PckCertChain,
    EcdsaSigAuxData,
}
