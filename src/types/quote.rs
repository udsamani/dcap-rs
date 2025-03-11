use anyhow::{anyhow, bail, Context};
use p256::ecdsa::Signature;
use sha2::{Sha256, Digest};
use x509_cert::certificate::CertificateInner;
use zerocopy::{little_endian, AsBytes};

use crate::utils;

use super::{report::{EnclaveReportBody, TdxReportBody}, sgx_x509::SgxPckExtension};


const QUOTE_V3: u16 = 3;
const QUOTE_V4: u16 = 4;
const SGX_TEE_TYPE: u32 = 0x00000000;
const TDX_TEE_TYPE: u32 = 0x00000081;

/// A DCAP quote, used for verification.
pub struct Quote<'a> {
    /// Header of the SGX Quote data structure.
    pub header: QuoteHeader,

    /// Software Vendor enclave report.
    pub body: QuoteBody,

    /// Signature of the quote body.
    pub support: QuoteSupportData<'a>,
}

impl<'a> Quote<'a> {

    pub fn read(bytes: &mut &'a [u8]) -> anyhow::Result<Self> {
        if bytes.len() < std::mem::size_of::<QuoteHeader>() {
            return Err(anyhow!("incorrect buffer size"));
        }

        // Read the quote header
        let quote_header = utils::read_array::<{std::mem::size_of::<QuoteHeader>()}>(bytes);
        let quote_header = QuoteHeader::try_from(quote_header)?;

        // Read the quote body and signature
        if quote_header.tee_type == SGX_TEE_TYPE {

            let quote_body = utils::read_array::<{std::mem::size_of::<EnclaveReportBody>()}>(bytes);
            let quote_body = EnclaveReportBody::try_from(quote_body)?;
            let quote_signature = QuoteSupportData::read(bytes)?;
            return Ok(Quote {
                header: quote_header,
                body: QuoteBody::SgxQuoteBody(quote_body),
                support: quote_signature,
            });

        } else if quote_header.tee_type == TDX_TEE_TYPE {

            let quote_body = utils::read_array::<{std::mem::size_of::<TdxReportBody>()}>(bytes);
            let quote_body = TdxReportBody::try_from(quote_body)?;
            let quote_signature = QuoteSupportData::read(bytes)?;

            return Ok(Quote {
                header: quote_header,
                body: QuoteBody::TdxQuoteBody(quote_body),
                support: quote_signature,
            });

        } else {
            return Err(anyhow!("unsupported quote version"));
        }
    }
}


/// Header of the SGX Quote data structure.
///
/// We use zerocopy for zero-copy parsing of the quote header from raw bytes.
/// This allows us to safely interpret the raw byte slice as a structured type without copying the data.
/// Benefits:
///
/// 1. Performance: Avoids memory allocation and copying of bytes
/// 2. Safety: Ensures the struct layout is compatible with the raw bytes through compile-time checks
/// 3. Direct memory mapping: Can read directly from memory-mapped files or network buffers
///
/// The FromBytes trait ensures the type is safe to interpret from any byte sequence
/// The FromZeroes trait ensures the type is safe to create from zero bytes
#[derive(Debug, zerocopy::FromBytes, zerocopy::FromZeroes)]
#[repr(C)]
pub struct QuoteHeader {
    /// Version of the quote data structure.
    /// (0)
    pub version: little_endian::U16,

    /// Type of attestation key used by the quoting enclave.
    /// 2 (ECDSA-256-with-P-256 curve)
    /// 3 (ECDSA-384-with-P-384 curve)
    /// (2)
    pub attestation_key_type: little_endian::U16,

    /// TEE for this Attestation
    /// 0x00000000: SGX
    /// 0x00000081: TDX
    /// (4)
    pub tee_type: u32,

    /// Security Version of the Quoting Enclave
    /// (8)
    pub qe_svn: little_endian::U16,

    /// Security Version of the PCE - 0 (Only applicable for SGX Quotes)
    /// (10)
    pub pce_svn: little_endian::U16,

    /// Unique identifier of the QE Vendor.
    /// Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
    /// (12)
    pub qe_vendor_id: [u8; 16],

    /// Custom user-defined data. For the Intel® SGX and TDX DCAP Quote Generation Libraries,
    /// the first 16 bytes contain a Platform Identifier that is used to link a PCK Certificate to an Enc(PPID).
    /// (28)
    pub user_data: [u8; 20],

    // Total size: 48 bytes
}

impl TryFrom<[u8; std::mem::size_of::<QuoteHeader>()]> for QuoteHeader {
    type Error = anyhow::Error;

    fn try_from(value: [u8; std::mem::size_of::<QuoteHeader>()]) -> Result<Self, Self::Error> {

        let quote_header = <Self as zerocopy::FromBytes>::read_from(&value)
            .expect("failed to read quote header");

        if quote_header.version.get() != QUOTE_V3 && quote_header.version.get() != QUOTE_V4 {
            return Err(anyhow!("unsupported quote version"));
        }

        Ok(quote_header)
    }
}


/// Body of the Quote data structure.
#[derive(Debug)]
pub enum QuoteBody {
    SgxQuoteBody(EnclaveReportBody),
    TdxQuoteBody(TdxReportBody),
}

impl QuoteBody {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::SgxQuoteBody(body) => body.as_bytes(),
            Self::TdxQuoteBody(body) => body.as_bytes(),
        }
    }
}
/// Support data for SGX Quotes
///
/// In the intel docs, this is A 4.4: "ECDSA 2560bit Quote Signature Data Structure"
///
/// This can be used to validate that the quoting enclave itself is valid, and then that
/// the quoting enclave has signed the ISV enclave report.
#[derive(Debug)]
pub struct QuoteSupportData<'a> {
    /// Signature of the report header + report by the attestation key.
    pub isv_signature: Signature,

    /// The public key used to generate the isv_signature.
    pub attestation_pub_key: [u8; 64],

    /// Report of the quoting enclave.
    pub qe_report_body: EnclaveReportBody,

    /// Signature of the quoting enclave report using the PCK cert key.
    pub qe_report_signature: Signature,

    /// sha256(attest pub key + auth data)
    pub auth_data: &'a [u8],

    /// Certificate chain of the PCK signer
    pub pck_cert_chain: Vec<CertificateInner>,

    /// Custom SGX extension that should be present on the PCK signer cert.
    pub pck_extension: SgxPckExtension,
}


impl <'a> QuoteSupportData<'a> {
    pub fn read(bytes: &mut &'a [u8]) -> Result<Self, anyhow::Error> {
        let signature_header: SgxEcdsaSignatureHeader = utils::read_from_bytes(bytes)
            .ok_or_else(|| anyhow!("incorrect buffer size"))?;

        if bytes.len() < signature_header.auth_data_size.get() as usize {
            return Err(anyhow!("incorrect buffer size"));
        }

        let auth_data = utils::read_bytes(bytes, signature_header.auth_data_size.get() as usize);
        let (cert_key_type, cert_data_size) = utils::read_from_bytes::<little_endian::U16>(bytes)
            .zip(utils::read_from_bytes::<little_endian::U32>(bytes))
            .ok_or_else(|| anyhow!("incorrect buffer size"))?;

        if cert_key_type.get() != CertificationKeyType::PckCertChain as u16 {
            return Err(anyhow!("unsupported cert key type"));
        }

        let cert_data_size = cert_data_size.get() as usize;

        if bytes.len() < cert_data_size {
            return Err(anyhow!("remaining data does not match expected size"));
        }

        let pck_cert_chain = utils::read_bytes(bytes, cert_data_size);

        // Strip Zero Byte If Present
        let pck_cert_chain = pck_cert_chain.strip_suffix(&[0]).unwrap_or(pck_cert_chain);
        let pck_cert_chain = CertificateInner::load_pem_chain(pck_cert_chain).context("CertChain")?;

        let pck_extension = pck_cert_chain
            .first()
            .context("CertChain")?
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|extensions|
                extensions
                    .iter()
                    .find(|ext| SgxPckExtension::is_pck_ext(ext.extn_id.to_string()))
            )
            .ok_or_else(|| anyhow!("PCK Certificate does not contain a SGX Extension"))?;

        let pck_extension = SgxPckExtension::from_der(pck_extension.extn_value.as_bytes())
            .context("PCK Extension")?;

        Ok(QuoteSupportData {
            isv_signature: Signature::from_slice(&signature_header.isv_signature).context("ISV Signature")?,
            attestation_pub_key: signature_header.attestation_pub_key,
            qe_report_body: signature_header.qe_report_body,
            qe_report_signature: Signature::from_slice(&signature_header.qe_report_signature).context("QE Report Signature")?,
            auth_data,
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
pub struct SgxEcdsaSignatureHeader {
    pub isv_signature: [u8; 64],
    pub attestation_pub_key: [u8; 64],
    pub qe_report_body: EnclaveReportBody,
    pub qe_report_signature: [u8; 64],
    auth_data_size: little_endian::U16,
}


#[derive(Debug, zerocopy::FromBytes, zerocopy::FromZeroes)]
pub struct TdxEcdsaSignatureHeader {
    pub isv_signature: [u8; 64],
    pub attestation_pub_key: [u8; 64],
}

/// Quote support data for TDX Quotes
#[derive(Debug)]
pub struct TdxQuoteSupportData {
    /// Signature of the report header + report by the attestation key.
    pub isv_signature: Signature,

    /// The public key used to generate the isv_signature.
    pub attestation_pub_key: Signature,

    /// Certificate chain of the PCK signer
    pub pck_cert_chain: Vec<CertificateInner>,

    /// Custom SGX extension that should be present on the PCK signer cert.
    pub pck_extension: SgxPckExtension,
}


impl <'a> TdxQuoteSupportData {
    pub fn read(bytes: &mut &'a [u8]) -> Result<Self, anyhow::Error> {
        let signature_header: TdxEcdsaSignatureHeader = utils::read_from_bytes(bytes)
            .ok_or_else(|| anyhow!("incorrect buffer size"))?;


        let (cert_key_type, cert_data_size) = utils::read_from_bytes::<little_endian::U16>(bytes)
            .zip(utils::read_from_bytes::<little_endian::U32>(bytes))
            .ok_or_else(|| anyhow!("incorrect buffer size"))?;

        if cert_key_type.get() != CertificationKeyType::PckCertChain as u16 {
            return Err(anyhow!("unsupported cert key type"));
        }

        let cert_data_size = cert_data_size.get() as usize;

        if bytes.len() < cert_data_size {
            return Err(anyhow!("remaining data does not match expected size"));
        }

        let pck_cert_chain = utils::read_bytes(bytes, cert_data_size);

        // Strip Zero Byte If Present
        let pck_cert_chain = pck_cert_chain.strip_suffix(&[0]).unwrap_or(pck_cert_chain);
        let pck_cert_chain = CertificateInner::load_pem_chain(pck_cert_chain).context("CertChain")?;

        let pck_extension = pck_cert_chain
            .first()
            .context("CertChain")?
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|extensions|
                extensions
                    .iter()
                    .find(|ext| SgxPckExtension::is_pck_ext(ext.extn_id.to_string()))
            )
            .ok_or_else(|| anyhow!("PCK Certificate does not contain a SGX Extension"))?;

        let pck_extension = SgxPckExtension::from_der(pck_extension.extn_value.as_bytes())
            .context("PCK Extension")?;

        Ok(TdxQuoteSupportData {
            isv_signature: Signature::from_slice(&signature_header.isv_signature).context("ISV Signature")?,
            attestation_pub_key: Signature::from_slice(&signature_header.attestation_pub_key).context("Attestation Pub Key")?,
            pck_cert_chain,
            pck_extension,
        })
    }
}

#[derive(Debug, PartialEq)]
enum CertificationKeyType {
    _PpidClearText = 1,
    _PpidRsa2048Encrypted,
    _PpidRsa3072Encrypted,
    _PckCleartext,
    PckCertChain,
    _EcdsaSigAuxData
}
