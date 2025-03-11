pub mod trust_store;
pub mod types;
pub mod utils;

use std::time::SystemTime;

use anyhow::{anyhow, bail, Context};
use p256::ecdsa::{signature::Verifier, VerifyingKey};
use trust_store::TrustStore;
use types::{
    collateral::Collateral,
    quote::{Quote, TDX_TEE_TYPE},
    sgx_x509::SgxPckExtension,
    tcb_info::{TcbInfo, TcbStanding},
    VerifiedOutput,
};
use utils::Expireable;
use zerocopy::AsBytes;

pub fn verify_dcap_quote(
    current_time: SystemTime,
    collateral: Collateral,
    quote: Quote,
) -> anyhow::Result<VerifiedOutput> {
    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK
    //    certificate, and that no keys in the chain have been revoked.
    let tcb_info = verify_integrity(current_time, &collateral, &quote)?;

    // 2. Verify the Quoting Enclave source and all signatures in the Quote.
    verify_quote(&collateral, &quote)?;

    // 3. Verify the status of Intel SGX TCB described in the chain.
    let tcb_standing = verify_tcb_status(&tcb_info, &quote.signature.pck_extension)?;
    let (advisory_ids, mut tcb_status) = match tcb_standing {
        TcbStanding::UpToDate => (None, types::tcb_info::TcbStatus::UpToDate),
        TcbStanding::SWHardeningNeeded { advisory_ids } => (
            Some(advisory_ids),
            types::tcb_info::TcbStatus::SWHardeningNeeded,
        ),
    };

    // 4. If TDX type then verify the status of TDX Module status and converge and send
    if quote.header.tee_type == TDX_TEE_TYPE {
        let tdx_module_status =
            tcb_info.verify_tdx_module(quote.body.as_tdx_report_body().unwrap())?;
        tcb_status = TcbInfo::convere_tcb_status_with_tdx_module(tcb_status, tdx_module_status);
    }

    Ok(VerifiedOutput {
        quote_version: quote.header.version.get(),
        tee_type: quote.header.tee_type,
        tcb_status,
        fmspc: quote.signature.pck_extension.fmspc,
        quote_body: quote.body,
        advisory_ids,
    })
}

fn verify_integrity(
    current_time: SystemTime,
    collateral: &Collateral,
    quote: &Quote,
) -> anyhow::Result<types::tcb_info::TcbInfo> {
    if !collateral.tcb_info_issuer_chain.valid_at(current_time) {
        bail!("expired tcb info issuer chain");
    }

    if !collateral.pck_crl_issuer_chain.valid_at(current_time) {
        bail!("expired pck crl issuer chain");
    }

    if !quote.signature.pck_cert_chain.valid_at(current_time) {
        bail!("expired pck cert chain");
    }

    let root_ca = collateral
        .tcb_info_issuer_chain
        .last()
        .context("tcb issuer chain is empty")?;

    // Verify the root certificate is self issued
    if root_ca.tbs_certificate.issuer != root_ca.tbs_certificate.subject {
        bail!("root certificate is not self issued");
    }

    // Should we validate that it is Intel Root CA ?
    // The idea would be to have the INTEL_ROOT_CA in memory.
    // TODO(udit): Identify whether the above is needed ?

    // Build initial trust store with the root certificate
    let mut trust_store = TrustStore::new(current_time, vec![root_ca.clone()])?;

    // Verify that the CRL is signed by Intel and add it to the store.
    trust_store
        .push_unverified_crl(collateral.root_ca_crl.clone())
        .context("failed to verify root ca crl")?;

    // Verify PCK CRL Chain and add it to the store.
    let pck_issuer = trust_store
        .verify_chain_leaf(&collateral.pck_crl_issuer_chain)
        .context("failed to verify pck crl issuer chain")?;

    // Verify the pck crl and add it to the store.
    pck_issuer
        .pk
        .verify(&collateral.pck_crl)
        .map_err(|e| anyhow::anyhow!("failed to verify pck crl signature: {}", e))?;
    if !collateral.pck_crl.valid_at(current_time) {
        bail!("expired pck crl");
    }
    trust_store.push_trusted_crl(collateral.pck_crl.clone());

    // Verify TCB Info Issuer Chain
    let tcb_issuer = trust_store
        .verify_chain_leaf(&collateral.tcb_info_issuer_chain)
        .context("failed to verify tcb info issuer chain")?;

    // Get TCB Signer Public Key
    let tcb_signer = tcb_issuer
        .cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("missing tcb signer public key")?;

    // We are making big assumption here that the key is ECDSA P-256
    let tcb_signer = p256::ecdsa::VerifyingKey::from_sec1_bytes(tcb_signer)
        .context("invalid tcb signer public key")?;

    // Verify the TCB Info
    let tcb_info = collateral
        .tcb_info
        .as_tcb_info_and_verify(tcb_signer)
        .context("failed to verify tcb info signature")?;

    // Verify the quote's pck signing certificate chain
    let _pck_signer = trust_store
        .verify_chain_leaf(&quote.signature.pck_cert_chain)
        .context("failed to verify quote support pck signing certificate chain")?;

    // Verify the quote identity issuer chain
    let _qe_id_issuer = trust_store
        .verify_chain_leaf(&collateral.qe_identity_issuer_chain)
        .context("failed to verify pck crl issuer certificate chain")?;

    Ok(tcb_info)
}

fn verify_quote(collateral: &Collateral, quote: &Quote) -> anyhow::Result<()> {
    verify_quote_enclave_source(collateral, quote)?;
    verify_quote_signatures(quote)?;
    Ok(())
}

/// Verify the quote enclave source
fn verify_quote_enclave_source(collateral: &Collateral, quote: &Quote) -> anyhow::Result<()> {
    let qe_identity = collateral
        .qe_identity
        .validate_as_enclave_identity(
            &VerifyingKey::from_sec1_bytes(
                collateral.qe_identity_issuer_chain[0]
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .as_bytes()
                    .context("missing qe identity public key")?,
            )
            .context("failed to verify quote enclave identity")?,
        )
        .context("failed to verify quote enclave identity")?;

    // Compare the mr_signer values
    if qe_identity.mrsigner != quote.signature.qe_report_body.mr_signer {
        bail!(
            "invalid qe mrsigner, expected {} but got {}",
            hex::encode(qe_identity.mrsigner),
            hex::encode(quote.signature.qe_report_body.mr_signer)
        );
    }

    // Compare the isv_prod_id values
    if qe_identity.isvprodid != quote.signature.qe_report_body.isv_prod_id.get() {
        bail!(
            "invalid qe isv_prod_id, expected {} but got {}",
            qe_identity.isvprodid,
            quote.signature.qe_report_body.isv_prod_id.get()
        );
    }

    // Compare the attribute values
    let qe_report_attributes = quote.signature.qe_report_body.sgx_attributes;
    let calculated_mask = qe_identity
        .attributes_mask
        .iter()
        .zip(qe_report_attributes.iter())
        .map(|(&mask, &attribute)| mask & attribute);

    if calculated_mask
        .zip(qe_identity.attributes)
        .any(|(masked, identity)| masked != identity)
    {
        bail!("qe attrtibutes mismatch");
    }

    Ok(())
}

/// Verify the quote signatures.
fn verify_quote_signatures(quote: &Quote) -> anyhow::Result<()> {
    let pck_pk_bytes = quote.signature.pck_cert_chain[0]
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("missing pck public key")?;

    let pck_pkey = VerifyingKey::from_sec1_bytes(pck_pk_bytes)
        .map_err(|e| anyhow!("failed to parse pck public key: {}", e))?;

    pck_pkey
        .verify(
            quote.signature.qe_report_body.as_bytes(),
            &quote.signature.qe_report_signature,
        )
        .map_err(|e| anyhow!("failed to verify qe report signature. {e}"))?;

    quote.signature.verify_qe_report()?;

    let mut key = [0u8; 65];
    key[0] = 4;
    key[1..].copy_from_slice(&quote.signature.attestation_pub_key);
    let attest_key = VerifyingKey::from_sec1_bytes(&key)
        .map_err(|e| anyhow!("failed to parse attest key: {e}"))?;

    let data = quote.body.as_bytes();
    let sig = quote.signature.isv_signature;
    attest_key
        .verify(data, &sig)
        .context("failed to verify quote signature")?;

    Ok(())
}

/// Ensure the latest tcb info is not revoked, and is either up to date or only needs a configuration
/// change.
fn verify_tcb_status(
    tcb_info: &TcbInfo,
    pck_extension: &SgxPckExtension,
) -> anyhow::Result<TcbStanding> {
    // Make sure the tcb_info matches the enclave's model/PCE version
    if pck_extension.fmspc != tcb_info.fmspc {
        return Err(anyhow::anyhow!(
            "tcb fmspc mismatch (pck extension: {:?}, tcb_info: {:?})",
            pck_extension.fmspc,
            tcb_info.fmspc
        ));
    }

    if pck_extension.pceid != tcb_info.pce_id {
        return Err(anyhow::anyhow!(
            "tcb pceid mismatch (pck extension: {:?}, tcb_info: {:?})",
            pck_extension.pceid,
            tcb_info.pce_id
        ));
    }

    TcbStanding::lookup(pck_extension, tcb_info)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parse_tdx_quote() {
        let bytes = include_bytes!("../data/quote_tdx.bin");
        let quote = Quote::read(&mut bytes.as_slice()).unwrap();
        println!("{:?}", quote);
    }

    #[test]
    fn parse_sgx_quote() {
        let bytes = include_bytes!("../data/quote_sgx.bin");
        let quote = Quote::read(&mut bytes.as_slice()).unwrap();
        println!("{:?}", quote);
    }
}
