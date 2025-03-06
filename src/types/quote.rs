use p256::ecdsa::Signature;
use x509_cert::certificate::CertificateInner;

use super::report::{EnclaveReportBody, TdxReportBody};

/// A DCAP quote, used for verification.
pub struct Quote {
    /// Header of the SGX Quote data structure.
    pub header: QuoteHeader,

    /// Software Vendor enclave report.
    pub body: QuoteBody,
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
    /// [2 bytes]
    pub version: u16,

    /// Type of attestation key used by the quoting enclave.
    /// 2 (ECDSA-256-with-P-256 curve)
    /// 3 (ECDSA-384-with-P-384 curve)
    /// [2 bytes]
    pub attestation_key_type: u16,

    /// TEE for this Attestation
    /// 0x00000000: SGX
    /// 0x00000081: TDX
    /// [4 bytes]
    pub tee_type: u32,

    /// Security Version of the Quoting Enclave
    /// [2 bytes]
    pub qe_svn: [u8; 2],

    /// Security Version of the PCE - 0 (Only applicable for SGX Quotes)
    /// [2 bytes]
    pub pce_svn: [u8; 2],

    /// Unique identifier of the QE Vendor.
    /// Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
    /// [16 bytes]
    pub qe_vendor_id: [u8; 16],

    /// Custom user-defined data. For the Intel® SGX and TDX DCAP Quote Generation Libraries,
    /// the first 16 bytes contain a Platform Identifier that is used to link a PCK Certificate to an Enc(PPID).
    /// [20 bytes]
    pub user_data: [u8; 20],
}


/// Body of the Quote data structure.
pub enum QuoteBody {
    SgxQuoteBody(EnclaveReportBody),
    TdxQuoteBody(TdxReportBody),
}

/// Quote signature data for SGX and TDX Quotes
#[derive(Debug)]
pub enum QuoteSignatureData<'a> {
    SgxSignatureData(SgxSignatureData<'a>),
    TdxSignatureData(TdxSignatureData),
}


/// In the intel docs, this is A 4.4: "ECDSA 2560bit Quote Signature Data Structure"
///
/// This can be used to validate that the quoting enclave itself is valid, and then that
/// the quoting enclave has signed the ISV enclave report.
#[derive(Debug)]
pub struct SgxSignatureData<'a> {
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
}


/// Quote signature data for TDX Quotes
#[derive(Debug)]
pub struct TdxSignatureData {
    /// Signature of the report header + report by the attestation key.
    pub isv_signature: Signature,

    /// The public key used to generate the isv_signature.
    pub attestation_pub_key: [u8; 64],

    /// Certificate chain of the PCK signer
    pub pck_cert_chain: Vec<CertificateInner>,
}
