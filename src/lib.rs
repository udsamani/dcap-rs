pub mod types;
pub mod utils;
pub mod constants;
pub mod trust_store;

use std::time::SystemTime;

use anyhow::{bail, Context};
use p256::ecdsa::{signature::Verifier, VerifyingKey};
use trust_store::TrustStore;
use types::{collateral::Collateral, quote::Quote, quotes::{version_3::QuoteV3, version_4::QuoteV4}, tcbinfo::TcbInfo, VerifiedOutput};
use x509_parser::certificate::X509Certificate;
use utils::Expireable;



pub fn verify_dcap_quote(
    current_time: SystemTime,
    collateral: Collateral,
    quote: Quote,
) -> anyhow::Result<VerifiedOutput> {

    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK
    //    certificate, and that no keys in the chain have been revoked.
    let tcb_info = verify_integrity(current_time, collateral, quote)?;


    // 2. Verify the Quoting Enclave source and all signatures in the Quote.


    // 3. Verify the status of Intel SGX TCB described in the chain.

    todo!()

}



fn verify_integrity(
    current_time: SystemTime,
    collateral: Collateral,
    quote: Quote,
) -> anyhow::Result<types::tcb_info::TcbInfo> {

    if !collateral.tcb_info_issuer_chain.valid_at(current_time) {
        bail!("expired tcb info issuer chain");
    }

    if !collateral.pck_crl_issuer_chain.valid_at(current_time) {
        bail!("expired pck crl issuer chain");
    }

    if !quote.support.pck_cert_chain.valid_at(current_time) {
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
        .tcb_info.as_tcb_info_and_verify(tcb_signer)
        .context("failed to verify tcb info signature")?;

    // Verify the quote's pck signing certificate chain
    let _pck_signer = trust_store
        .verify_chain_leaf(&quote.support.pck_cert_chain)
        .context("failed to verify quote support pck signing certificate chain")?;

    // Verify the quote identity issuer chain
    let _qe_id_issuer = trust_store
        .verify_chain_leaf(&collateral.qe_identity_issuer_chain)
        .context("failed to verify pck crl issuer certificate chain")?;

    Ok(tcb_info)
}


fn verify_quote(
    collateral: &Collateral,
    quote: &Quote
) -> anyhow::Result<()> {

    verify_quote_enclave_source(collateral, quote)?;

    Ok(())

}

/// Verify the quote enclave source
fn verify_quote_enclave_source(
    collateral: &Collateral,
    quote: &Quote
) -> anyhow::Result<()> {

    let qe_identity = collateral
        .qe_identity
        .validate_as_enclave_identity(
            &VerifyingKey::from_sec1_bytes(
                collateral.qe_identity_issuer_chain[0]
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .as_bytes()
                    .context("missing qe identity public key")?
            )
            .context("failed to verify quote enclave identity")?
    ).context("failed to verify quote enclave identity")?;

    // Compare the mr_signer values
    if qe_identity.mrsigner != quote.support.qe_report_body.mr_signer {
        bail!(
            "invalid qe mrsigner, expected {} but got {}",
            hex::encode(qe_identity.mrsigner),
            hex::encode(quote.support.qe_report_body.mr_signer)
        );
    }

    // Compare the isv_prod_id values
    if qe_identity.isvprodid != quote.support.qe_report_body.isv_prod_id.get() {
        bail!(
            "invalid qe isv_prod_id, expected {} but got {}",
            qe_identity.isvprodid,
            quote.support.qe_report_body.isv_prod_id.get()
        );
    }

    // Compare the attribute values
    let qe_report_attributes = quote.support.qe_report_body.sgx_attributes;
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





#[cfg(test)]
mod tests {
    use crate::types::tcbinfo::{TcbInfoV2, TcbInfoV3};
    use crate::types::quotes::{version_4::QuoteV4, version_3::QuoteV3};
    use crate::types::collaterals::IntelCollateral;

    use crate::utils::cert::{hash_crl_keccak256, hash_x509_keccak256, parse_crl_der, parse_pem, parse_x509_der, verify_crl};
    use crate::utils::tcbinfo::{validate_tcbinfov2, validate_tcbinfov3};
    use crate::utils::quotes::{
        version_3::verify_quote_dcapv3,
        version_4::verify_quote_dcapv4
    };

    // Pinned September 10th, 2024, 6:49am GMT
    // there's no need for constant sample collateral updates
    const PINNED_TIME: u64 = 1725950994;

    #[test]
    fn test_root_crl_verify() {
        let intel_sgx_root_ca = parse_x509_der(include_bytes!("../data/Intel_SGX_Provisioning_Certification_RootCA.cer"));
        let intel_sgx_root_ca_crl = parse_crl_der(include_bytes!("../data/intel_root_ca_crl.der"));

        assert!(verify_crl(&intel_sgx_root_ca_crl, &intel_sgx_root_ca));
    }

    #[test]
    fn test_tcbinfov3() {
        // let current_time = chrono::Utc::now().timestamp() as u64;

        let tcbinfov3_json = include_str!("../data/tcbinfov3_00806f050000.json");
        let tcbinfov3: TcbInfoV3 = serde_json::from_str(tcbinfov3_json).unwrap();
        let tcbinfov3_serialize = serde_json::to_string(&tcbinfov3).unwrap();
        assert!(tcbinfov3_serialize == tcbinfov3_json);

        let sgx_signing_cert_pem = &parse_pem(include_bytes!("../data/signing_cert.pem")).unwrap()[0];
        let sgx_signing_cert = parse_x509_der(&sgx_signing_cert_pem.contents);

        assert!(validate_tcbinfov3(&tcbinfov3, &sgx_signing_cert, PINNED_TIME));
    }

    #[test]
    fn test_tcbinfov2() {
        // let current_time = chrono::Utc::now().timestamp() as u64;

        let tcbinfov2_json = include_str!("../data/tcbinfov2.json");
        let tcbinfov2: TcbInfoV2 = serde_json::from_str(tcbinfov2_json).unwrap();
        let tcbinfov2_serialize = serde_json::to_string(&tcbinfov2).unwrap();
        assert!(tcbinfov2_serialize == tcbinfov2_json);

        let sgx_signing_cert_pem = &parse_pem(include_bytes!("../data/signing_cert.pem")).unwrap()[0];
        let sgx_signing_cert = parse_x509_der(&sgx_signing_cert_pem.contents);

        assert!(validate_tcbinfov2(&tcbinfov2, &sgx_signing_cert, PINNED_TIME));
    }

    #[test]
    fn test_quotev4() {
        let quotev4_slice = include_bytes!("../data/quote_tdx_00806f050000.dat");
        let quotev4 = QuoteV4::from_bytes(quotev4_slice);
        assert_eq!(quotev4.header.version, 4);
    }

    #[test]
    fn test_verifyv3() {
        // let current_time = chrono::Utc::now().timestamp() as u64;

        let mut collaterals = IntelCollateral::new();
        collaterals.set_tcbinfo_bytes(include_bytes!("../data/tcbinfov2.json"));
        collaterals.set_qeidentity_bytes(include_bytes!("../data/qeidentityv2.json"));
        collaterals.set_intel_root_ca_der(include_bytes!("../data/Intel_SGX_Provisioning_Certification_RootCA.cer"));
        collaterals.set_sgx_tcb_signing_pem(include_bytes!("../data/signing_cert.pem"));
        collaterals.set_sgx_intel_root_ca_crl_der(include_bytes!("../data/intel_root_ca_crl.der"));
        collaterals.set_sgx_platform_crl_der(include_bytes!("../data/pck_platform_crl.der"));
        collaterals.set_sgx_processor_crl_der(include_bytes!("../data/pck_processor_crl.der"));


        let dcap_quote_bytes = hex::decode("030002000000000009000e00939a7233f79c4ca9940a0db3957f0607ad04024c9dfb382baf51ca3e5d6cb6e6000000000c0c100fffff0100000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000e700000000000000a4f45c39dac622cb1dd32ddb35a52ec92db41d0fa88a1c911c49e59c534f61cd00000000000000000000000000000000000000000000000000000000000000001bda23eb3a807dfe735ddcebbfa2eac05e04a00df2804296612f770b594180ba0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ca100000e78d2532cbef391dea9a477119bc505b47e187f6f045636cce8bcf41604a099232eee31b3ef3827c442eb5d5981610480deb0625ed4b01c1ac2b0fb43e05efdeab8af342a611fb608193d9a47b8111654172adf2dabd2d428d28ebe094b9baa1f8f7e240b015af174d4f58a6b201946eee2097af02ed554909779ea2d9f3c1020c0c100fffff0100000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000e700000000000000192aa50ce1c0cef03ccf89e7b5b16b0d7978f5c2b1edcf774d87702e8154d8bf00000000000000000000000000000000000000000000000000000000000000008c4f5775d796503e96137f77c68a829a0056ac8ded70140b081b094490c57bff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a82754acc7010b3c087c6425ccf47033f711fa44776c6df3cf744864a063657b00000000000000000000000000000000000000000000000000000000000000006cf7ecfde138b32bbf6aec5e260f8bb6277cc2876ea144c3995d2afc0e6baa3525d91884672bf2832c23a6ebf85a165b45af53c836a31168ff7deaec0dd9c82c2000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0500620e00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494945386a4343424a6d674177494241674956414b7750766270377a6f7a50754144646b792b6f526e356f36704d754d416f4743437147534d343942414d430a4d484178496a416742674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d0a45556c756447567349454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155450a4341774351304578437a414a42674e5642415954416c56544d4234584454497a4d4467794e4449784d7a557a4d6c6f5844544d774d4467794e4449784d7a557a0a4d6c6f77634445694d434147413155454177775a535735305a5777675530645949464244537942445a584a3061575a70593246305a5445614d426747413155450a43677752535735305a577767513239796347397959585270623234784644415342674e564241634d43314e68626e526849454e7359584a684d517377435159440a5651514944414a445154454c4d416b474131554542684d4356564d775754415442676371686b6a4f5051494242676771686b6a4f50514d4242774e43414154450a764b6a754b66376969723832686d2b4d5a4151452b6847643349716d53396235634e63484a754b7a5a445970626f35496a344c7a7176704f503830706f4152730a59504233594e355537704d3777644936314b66716f344944446a434341776f77487759445652306a42426777466f41556c5739647a62306234656c4153636e550a3944504f4156634c336c5177617759445652306642475177596a42676f46366758495a616148523063484d364c79396863476b7564484a316333526c5a484e6c0a636e5a705932567a4c6d6c75644756734c6d4e766253397a5a3367765932567964476c6d61574e6864476c76626939324d7939775932746a636d772f593245390a6347786864475a76636d306d5a57356a62325270626d63395a4756794d4230474131556444675157424251695a7667373930317a3171554d3874534c754358580a6571314c6f54414f42674e56485138424166384542414d434273417744415944565230544151482f4241497741444343416a734743537147534962345451454e0a41515343416977776767496f4d42344743697147534962345451454e41514545454358343464705036434c5154772f785543575448306b776767466c42676f710a686b69472b453042445145434d4949425654415142677371686b69472b45304244514543415149424444415142677371686b69472b45304244514543416749420a4444415142677371686b69472b4530424451454341774942417a415142677371686b69472b4530424451454342414942417a415242677371686b69472b4530420a4451454342514943415038774551594c4b6f5a496876684e41513042416759434167442f4d42414743797147534962345451454e41514948416745424d4241470a43797147534962345451454e41514949416745414d42414743797147534962345451454e4151494a416745414d42414743797147534962345451454e4151494b0a416745414d42414743797147534962345451454e4151494c416745414d42414743797147534962345451454e4151494d416745414d42414743797147534962340a5451454e4151494e416745414d42414743797147534962345451454e4151494f416745414d42414743797147534962345451454e41514950416745414d4241470a43797147534962345451454e41514951416745414d42414743797147534962345451454e415149524167454e4d42384743797147534962345451454e415149530a4242414d44414d442f2f38424141414141414141414141414d42414743697147534962345451454e41514d45416741414d42514743697147534962345451454e0a4151514542674267616741414144415042676f71686b69472b45304244514546436745424d42344743697147534962345451454e4151594545424531784169510a72743945363234433159516b497034775241594b4b6f5a496876684e41513042427a41324d42414743797147534962345451454e415163424151482f4d4241470a43797147534962345451454e41516343415145414d42414743797147534962345451454e41516344415145414d416f4743437147534d343942414d43413063410a4d45514349445a6f63514c6478362b4f2b586d4f6b766f6b654133345a617261342b6539534e5877344b68396d5876574169415479695a6e495932474f3466670a4938673342666c4e434f56446e42505270507559377274484e77335470513d3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436c6a4343416a32674177494241674956414a567658633239472b487051456e4a3150517a7a674658433935554d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484178496a41670a42674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d45556c75644756730a49454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b474131554543417743513045780a437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454e53422f377432316c58534f0a3243757a7078773734654a423732457944476757357258437478327456544c7136684b6b367a2b5569525a436e71523770734f766771466553786c6d546c4a6c0a65546d693257597a33714f42757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f536347724442530a42674e5648523845537a424a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e5648513445466751556c5739640a7a62306234656c4153636e553944504f4156634c336c517744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159420a4166384341514177436759494b6f5a497a6a30454177494452774177524149675873566b6930772b6936565947573355462f32327561586530594a446a3155650a6e412b546a44316169356343494359623153416d4435786b66545670766f34556f79695359787244574c6d5552344349394e4b7966504e2b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a00").unwrap();
        let dcap_quote = QuoteV3::from_bytes(&dcap_quote_bytes);

        let verified_output = verify_quote_dcapv3(&dcap_quote, &collaterals, PINNED_TIME);

        println!("{:?}", verified_output);
        let root_hash = hash_x509_keccak256(&collaterals.get_sgx_intel_root_ca());
        let sign_hash = hash_x509_keccak256(&collaterals.get_sgx_tcb_signing());
        let crl_hash = hash_crl_keccak256(&collaterals.get_sgx_intel_root_ca_crl().unwrap());
        println!("{:?}", root_hash);
        println!("{:?}", sign_hash);
        println!("{:?}", crl_hash);
    }

    #[test]
    fn test_verifyv4() {
        // let current_time = chrono::Utc::now().timestamp() as u64;

        let mut collaterals = IntelCollateral::new();
        collaterals.set_tcbinfo_bytes(include_bytes!("../data/tcbinfov3_00806f050000.json"));
        collaterals.set_qeidentity_bytes(include_bytes!("../data/qeidentityv2_apiv4.json"));
        collaterals.set_intel_root_ca_der(include_bytes!("../data/Intel_SGX_Provisioning_Certification_RootCA.cer"));
        collaterals.set_sgx_tcb_signing_pem(include_bytes!("../data/signing_cert.pem"));
        collaterals.set_sgx_intel_root_ca_crl_der(include_bytes!("../data/intel_root_ca_crl.der"));
        collaterals.set_sgx_platform_crl_der(include_bytes!("../data/pck_platform_crl.der"));
        collaterals.set_sgx_processor_crl_der(include_bytes!("../data/pck_processor_crl.der"));


        let dcap_quote = QuoteV4::from_bytes(include_bytes!("../data/quote_tdx_00806f050000.dat"));

        let verified_output = verify_quote_dcapv4(&dcap_quote, &collaterals, PINNED_TIME);

        println!("{:?}", verified_output);
        let root_hash = hash_x509_keccak256(&collaterals.get_sgx_intel_root_ca());
        let sign_hash = hash_x509_keccak256(&collaterals.get_sgx_tcb_signing());
        let crl_hash = hash_crl_keccak256(&collaterals.get_sgx_intel_root_ca_crl().unwrap());
        println!("{:?}", root_hash);
        println!("{:?}", sign_hash);
        println!("{:?}", crl_hash);
    }
}
