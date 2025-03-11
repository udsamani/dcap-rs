mod body;
mod cert_data;
mod header;
mod signature;

use anyhow::anyhow;
pub use body::*;
pub use cert_data::*;
pub use header::*;
pub use signature::*;

use crate::utils;

use super::report::{EnclaveReportBody, TdxReportBody};

#[allow(non_snake_case)]
const QUOTE_V3: u16 = 3;
#[allow(non_snake_case)]
const QUOTE_V4: u16 = 4;

pub const SGX_TEE_TYPE: u32 = 0x00000000;
pub const TDX_TEE_TYPE: u32 = 0x00000081;

/// A DCAP quote, used for verification.
#[derive(Debug)]
pub struct Quote {
    /// Header of the SGX Quote data structure.
    pub header: QuoteHeader,

    /// Software Vendor enclave report.
    pub body: QuoteBody,

    /// Signature of the quote body.
    pub signature: QuoteSignatureData,
}

impl Quote {
    pub fn read(bytes: &mut &[u8]) -> anyhow::Result<Self> {
        if bytes.len() < std::mem::size_of::<QuoteHeader>() {
            return Err(anyhow!("incorrect buffer size"));
        }

        // Read the quote header
        let quote_header = utils::read_array::<{ std::mem::size_of::<QuoteHeader>() }>(bytes);
        let quote_header = QuoteHeader::try_from(quote_header)?;

        // Read the quote body and signature
        if quote_header.tee_type == SGX_TEE_TYPE {
            let quote_body =
                utils::read_array::<{ std::mem::size_of::<EnclaveReportBody>() }>(bytes);
            let quote_body = EnclaveReportBody::try_from(quote_body)?;
            let quote_signature = QuoteSignatureData::read(bytes, quote_header.version.get())?;
            return Ok(Quote {
                header: quote_header,
                body: QuoteBody::SgxQuoteBody(quote_body),
                signature: quote_signature,
            });
        } else if quote_header.tee_type == TDX_TEE_TYPE {
            let quote_body = utils::read_array::<{ std::mem::size_of::<TdxReportBody>() }>(bytes);
            let quote_body = TdxReportBody::try_from(quote_body)?;
            let quote_signature = QuoteSignatureData::read(bytes, quote_header.version.get())?;

            return Ok(Quote {
                header: quote_header,
                body: QuoteBody::TdxQuoteBody(quote_body),
                signature: quote_signature,
            });
        } else {
            return Err(anyhow!("unsupported quote version"));
        }
    }
}
