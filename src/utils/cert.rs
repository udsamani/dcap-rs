use x509_parser::prelude::*;
use x509_parser::oid_registry::asn1_rs::{Boolean, Sequence, FromDer, Oid, Integer, OctetString, oid, Enumerated};

use crate::types::cert::{SgxExtensions, SgxExtensionTcbLevel, PckPlatformConfiguration};
use crate::types::tcbinfo::TcbInfoV2;
use crate::types::TcbStatus;
use crate::utils::hash::{sha256sum, keccak256sum};
use crate::utils::crypto::verify_p256_signature_bytes;


pub fn hash_cert_keccak256(cert: &X509Certificate) -> [u8; 32] {
    keccak256sum(cert.tbs_certificate.as_ref())
}

pub fn hash_cert_sha256(cert: &X509Certificate) -> [u8; 32] {
    sha256sum(cert.tbs_certificate.as_ref())
}

pub fn parse_pem(raw_bytes: &[u8]) -> Result<Vec<Pem>, PEMError> {
    Pem::iter_from_buffer(raw_bytes).collect()
}

pub fn parse_der(raw_bytes: &[u8]) -> X509Certificate {
    let (_, cert) = X509Certificate::from_der(raw_bytes).unwrap();
    cert
}

pub fn parse_certchain<'a>(pem_certs: &'a[Pem]) -> Vec<X509Certificate<'a>> {
    pem_certs.iter().map(|pem| {
        pem.parse_x509().unwrap()
    }).collect()
}

pub fn verify_certificate(cert: &X509Certificate, signer_cert: &X509Certificate) -> bool {
    // verifies that the certificate is valid
    let data = cert.tbs_certificate.as_ref();
    let signature = cert.signature_value.as_ref();
    let public_key = signer_cert.public_key().subject_public_key.as_ref();
    verify_p256_signature_bytes(data, signature, public_key)
}

pub fn validate_certificate(_cert: &X509Certificate) -> bool {
    // TODO: check that the certificate is a valid cert.
    // i.e., make sure that the cert name is correct, issued by intel,
    // has not been revoked, etc.
    // for now, we'll just return true
    true
}

pub fn verify_certchain<'a>(certs: &'a [X509Certificate<'a>], root_cert: &X509Certificate<'a>) -> bool {
    // verify that the cert chain is valid
    let mut iter = certs.iter();
    let mut prev_cert = iter.next().unwrap();
    for cert in iter {
        // verify that the previous cert signed the current cert
        if !verify_certificate(prev_cert, cert) {
            return false;
        }
        // verify that the current cert is valid
        if !validate_certificate(prev_cert) {
            return false;
        }
        prev_cert = cert;
    }
    // verify that the root cert signed the last cert
    verify_certificate(prev_cert, root_cert)
}

pub fn get_asn1_bool<'a>(bytes: &'a[u8], oid_str: &str) -> (&'a[u8], bool) {
    let (k, asn1_seq) = Sequence::from_der(bytes).unwrap();
    let (l, asn1_oid) = Oid::from_der(asn1_seq.content.as_ref()).unwrap();
    assert!(oid_str.eq(&asn1_oid.to_id_string()));
    let (l, asn1_bool) = Boolean::from_der(l).unwrap();
    assert_eq!(l.len(), 0);
    (k, asn1_bool.bool())
}

pub fn get_asn1_uint64<'a>(bytes: &'a[u8], oid_str: &str) -> (&'a[u8], u64) {
    let (k, asn1_seq) = Sequence::from_der(bytes).unwrap();
    let (l, asn1_oid) = Oid::from_der(asn1_seq.content.as_ref()).unwrap();
    assert!(oid_str.eq(&asn1_oid.to_id_string()));
    let (l, asn1_int) = Integer::from_der(l).unwrap();
    assert_eq!(l.len(), 0);
    (k, asn1_int.as_u64().unwrap())
}

pub fn get_asn1_bytes<'a>(bytes: &'a[u8], oid_str: &str) -> (&'a[u8], Vec<u8>) {
    let (k, asn1_seq) = Sequence::from_der(bytes).unwrap();
    let (l, asn1_oid) = Oid::from_der(asn1_seq.content.as_ref()).unwrap();
    assert!(oid_str.eq(&asn1_oid.to_id_string()));
    let (l, asn1_bytes) = OctetString::from_der(l).unwrap();
    assert_eq!(l.len(), 0);
    (k, asn1_bytes.into_cow().to_vec())
}

pub fn extract_sgx_extension<'a>(cert: &'a X509Certificate<'a>) -> SgxExtensions {
    // https://download.01.org/intel-sgx/sgx-dcap/1.20/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf

    // <SGX Extensions OID>:
    //     <PPID OID>: <PPID value>
    //     <TCB OID>:
    //          <SGX TCB Comp01 SVN OID>: <SGX TCB Comp01 SVN value>
    //          <SGX TCB Comp02 SVN OID>: <SGX TCB Comp02 SVN value>
    //          …
    //          <SGX TCB Comp16 SVN OID>: <SGX TCB Comp16 SVN value>
    //          <PCESVN OID>: <PCESVN value>
    //          <CPUSVN OID>: <CPUSVN value>
    //     <PCE-ID OID>: <PCE-ID value>
    //     <FMSPC OID>: <FMSPC value>
    //     <SGX Type OID>: <SGX Type value>
    //     <PlatformInstanceID OID>: <PlatformInstanceID value>
    //     <Configuration OID>:
    //          <Dynamic Platform OID>: <Dynamic Platform flag value>
    //          <Cached Keys OID>: <Cached Keys flag value>
    //          <SMT Enabled OID>: <SMT Enabled flag value>

    // SGX Extensions       | 1.2.840.113741.1.13.1      | mandatory | ASN.1 Sequence
    // PPID                 | 1.2.840.113741.1.13.1.1    | mandatory | ASN.1 Octet String
    // TCB                  | 1.2.840.113741.1.13.1.2    | mandatory | ASN.1 Sequence
    // SGX TCB Comp01 SVN   | 1.2.840.113741.1.13.1.2.1  | mandatory | ASN.1 Integer 
    // SGX TCB Comp02 SVN   | 1.2.840.113741.1.13.1.2.2  | mandatory | ASN.1 Integer 
    // ...
    // SGX TCB Comp16 SVN   | 1.2.840.113741.1.13.1.2.16 | mandatory | ASN.1 Integer 
    // PCESVN               | 1.2.840.113741.1.13.1.2.17 | mandatory | ASN.1 Integer 
    // CPUSVN               | 1.2.840.113741.1.13.1.2.18 | mandatory | ASN.1 Integer 
    // PCE-ID               | 1.2.840.113741.1.13.1.3    | mandatory | ASN.1 Octet String
    // FMSPC                | 1.2.840.113741.1.13.1.4    | mandatory | ASN.1 Octet String
    // SGX Type             | 1.2.840.113741.1.13.1.5    | mandatory | ASN.1 Enumerated
    // Platform Instance ID | 1.2.840.113741.1.13.1.6    | optional  | ASN.1 Octet String
    // Configuration        | 1.2.840.113741.1.13.1.7    | optional  | ASN.1 Sequence
    // Dynamic Platform     | 1.2.840.113741.1.13.1.7.1  | optional  | ASN.1 Boolean
    // Cached Keys          | 1.2.840.113741.1.13.1.7.2  | optional  | ASN.1 Boolean
    // SMT Enabled          | 1.2.840.113741.1.13.1.7.3  | optional  | ASN.1 Boolean

    let sgx_extensions_bytes = cert.get_extension_unique(&oid!(1.2.840.113741.1.13.1)).unwrap().unwrap().value;

    let (_, sgx_extensions) = Sequence::from_der(sgx_extensions_bytes).unwrap();

    // we'll process the sgx extensions here...
    let mut i = sgx_extensions.content.as_ref();

    // let's define the required information to create the SgxExtensions struct
    let mut ppid = [0; 16];
    let mut tcb = SgxExtensionTcbLevel {
        sgxtcbcomp01svn: 0,
        sgxtcbcomp02svn: 0,
        sgxtcbcomp03svn: 0,
        sgxtcbcomp04svn: 0,
        sgxtcbcomp05svn: 0,
        sgxtcbcomp06svn: 0,
        sgxtcbcomp07svn: 0,
        sgxtcbcomp08svn: 0,
        sgxtcbcomp09svn: 0,
        sgxtcbcomp10svn: 0,
        sgxtcbcomp11svn: 0,
        sgxtcbcomp12svn: 0,
        sgxtcbcomp13svn: 0,
        sgxtcbcomp14svn: 0,
        sgxtcbcomp15svn: 0,
        sgxtcbcomp16svn: 0,
        pcesvn: 0,
        cpusvn: [0; 16],
    };
    let mut pceid = [0; 2];
    let mut fmspc = [0; 6];
    let mut sgx_type = 0;
    let mut platform_instance_id: Option<[u8; 16]> = None;
    let mut configuration: Option<PckPlatformConfiguration> = None;


    while i.len() > 0 {
        let (j, current_sequence) = Sequence::from_der(i).unwrap();
        i = j;
        let (j, current_oid) = Oid::from_der(current_sequence.content.as_ref()).unwrap();
        match current_oid.to_id_string().as_str() {
            "1.2.840.113741.1.13.1.1" => {
                let (k, ppid_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                ppid.copy_from_slice(ppid_bytes.as_ref());
            },
            "1.2.840.113741.1.13.1.2" => {
                let (k, tcb_sequence) = Sequence::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                // iterate through from 1 - 18
                let (k, sgxtcbcomp01svn) = get_asn1_uint64(tcb_sequence.content.as_ref(), "1.2.840.113741.1.13.1.2.1");
                let (k, sgxtcbcomp02svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.2");
                let (k, sgxtcbcomp03svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.3");
                let (k, sgxtcbcomp04svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.4");
                let (k, sgxtcbcomp05svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.5");
                let (k, sgxtcbcomp06svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.6");
                let (k, sgxtcbcomp07svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.7");
                let (k, sgxtcbcomp08svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.8");
                let (k, sgxtcbcomp09svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.9");
                let (k, sgxtcbcomp10svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.10");
                let (k, sgxtcbcomp11svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.11");
                let (k, sgxtcbcomp12svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.12");
                let (k, sgxtcbcomp13svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.13");
                let (k, sgxtcbcomp14svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.14");
                let (k, sgxtcbcomp15svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.15");
                let (k, sgxtcbcomp16svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.16");
                let (k, pcesvn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.17");
                let (k, cpusvn) = get_asn1_bytes(k, "1.2.840.113741.1.13.1.2.18");

                assert_eq!(k.len(), 0);
                // copy the bytes into the tcb struct
                tcb.sgxtcbcomp01svn = sgxtcbcomp01svn;
                tcb.sgxtcbcomp02svn = sgxtcbcomp02svn;
                tcb.sgxtcbcomp03svn = sgxtcbcomp03svn;
                tcb.sgxtcbcomp04svn = sgxtcbcomp04svn;
                tcb.sgxtcbcomp05svn = sgxtcbcomp05svn;
                tcb.sgxtcbcomp06svn = sgxtcbcomp06svn;
                tcb.sgxtcbcomp07svn = sgxtcbcomp07svn;
                tcb.sgxtcbcomp08svn = sgxtcbcomp08svn;
                tcb.sgxtcbcomp09svn = sgxtcbcomp09svn;
                tcb.sgxtcbcomp10svn = sgxtcbcomp10svn;
                tcb.sgxtcbcomp11svn = sgxtcbcomp11svn;
                tcb.sgxtcbcomp12svn = sgxtcbcomp12svn;
                tcb.sgxtcbcomp13svn = sgxtcbcomp13svn;
                tcb.sgxtcbcomp14svn = sgxtcbcomp14svn;
                tcb.sgxtcbcomp15svn = sgxtcbcomp15svn;
                tcb.sgxtcbcomp16svn = sgxtcbcomp16svn;
                tcb.pcesvn = pcesvn;
                tcb.cpusvn.copy_from_slice(cpusvn.as_ref());
            },
            "1.2.840.113741.1.13.1.3" => {
                let (k, pceid_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                pceid.copy_from_slice(pceid_bytes.as_ref());
            },
            "1.2.840.113741.1.13.1.4" => {
                let (k, fmspc_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                fmspc.copy_from_slice(fmspc_bytes.as_ref());
            },
            "1.2.840.113741.1.13.1.5" => {
                let (k, sgx_type_enum) = Enumerated::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                sgx_type = sgx_type_enum.0;
            },
            "1.2.840.113741.1.13.1.6" => {
                let (k, platform_instance_id_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                let mut temp = [0; 16];
                temp.copy_from_slice(platform_instance_id_bytes.as_ref());
                platform_instance_id = Some(temp);

            },
            "1.2.840.113741.1.13.1.7" => {
                let (k, configuration_seq) = Sequence::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                let mut configuration_temp = PckPlatformConfiguration {
                    dynamic_platform: None,
                    cached_keys: None,
                    smt_enabled: None,
                };
                // iterate through from 1 - 3, note that some of them might be optional.
                let mut k = configuration_seq.content.as_ref();
                while k.len() > 0 {
                    let (l, asn1_seq) = Sequence::from_der(k).unwrap();
                    k = l;
                    let (l, current_oid) = Oid::from_der(asn1_seq.content.as_ref()).unwrap();
                    match current_oid.to_id_string().as_str() {
                        "1.2.840.113741.1.13.1.7.1" => {
                            let (l, dynamic_platform_bool) = Boolean::from_der(l).unwrap();
                            assert_eq!(l.len(), 0);
                            configuration_temp.dynamic_platform = Some(dynamic_platform_bool.bool());
                        },
                        "1.2.840.113741.1.13.1.7.2" => {
                            let (l, cached_keys_bool) = Boolean::from_der(l).unwrap();
                            assert_eq!(l.len(), 0);
                            configuration_temp.cached_keys = Some(cached_keys_bool.bool());
                        },
                        "1.2.840.113741.1.13.1.7.3" => {
                            let (l, smt_enabled_bool) = Boolean::from_der(l).unwrap();
                            assert_eq!(l.len(), 0);
                            configuration_temp.smt_enabled = Some(smt_enabled_bool.bool());
                        },
                        _ => {
                            unreachable!("Unknown OID: {}", current_oid.to_id_string());
                        },
                    }
                }
                // done parsing...
                configuration = Some(configuration_temp);
            },
            _ => {
                unreachable!("Unknown OID: {}", current_oid.to_id_string());
            },
        }
    }

    SgxExtensions {
        ppid,
        tcb,
        pceid,
        fmspc,
        sgx_type,
        platform_instance_id,
        configuration,
    }
}

pub fn get_fmspc_tcbstatus(sgx_extensions: &SgxExtensions, tcb_info_root: &TcbInfoV2) -> TcbStatus {
    // we'll make sure the tcbinforoot is valid
    // check that fmspc is valid
    // check that pceid is valid

    // convert fmspc and pceid to string for comparison
    // println!("sgx_extensions fmspc: {:?}", hex::encode(sgx_extensions.fmspc));
    // println!("tcb_info_root fmspc: {:?}", tcb_info_root.tcb_info.fmspc);
    assert!(hex::encode(sgx_extensions.fmspc) == tcb_info_root.tcb_info.fmspc);
    assert!(hex::encode(sgx_extensions.pceid) == tcb_info_root.tcb_info.pce_id);
    
    // now that we are sure that fmspc and pceid is the same, we'll iterate through and find the tcbstatus
    // we assume that the tcb_levels are sorted in descending svn order
    // println!("sgx_extensions tcb: {:?}", sgx_extensions.tcb);
    for tcb_level in tcb_info_root.tcb_info.tcb_levels.iter() {
        let tcb = &tcb_level.tcb;
        // println!("tcb: {:?}", tcb);
        if tcb.sgxtcbcomp01svn <= sgx_extensions.tcb.sgxtcbcomp01svn &&
            tcb.sgxtcbcomp02svn <= sgx_extensions.tcb.sgxtcbcomp02svn &&
            tcb.sgxtcbcomp03svn <= sgx_extensions.tcb.sgxtcbcomp03svn &&
            tcb.sgxtcbcomp04svn <= sgx_extensions.tcb.sgxtcbcomp04svn &&
            tcb.sgxtcbcomp05svn <= sgx_extensions.tcb.sgxtcbcomp05svn &&
            tcb.sgxtcbcomp06svn <= sgx_extensions.tcb.sgxtcbcomp06svn &&
            tcb.sgxtcbcomp07svn <= sgx_extensions.tcb.sgxtcbcomp07svn &&
            tcb.sgxtcbcomp08svn <= sgx_extensions.tcb.sgxtcbcomp08svn &&
            tcb.sgxtcbcomp09svn <= sgx_extensions.tcb.sgxtcbcomp09svn &&
            tcb.sgxtcbcomp10svn <= sgx_extensions.tcb.sgxtcbcomp10svn &&
            tcb.sgxtcbcomp11svn <= sgx_extensions.tcb.sgxtcbcomp11svn &&
            tcb.sgxtcbcomp12svn <= sgx_extensions.tcb.sgxtcbcomp12svn &&
            tcb.sgxtcbcomp13svn <= sgx_extensions.tcb.sgxtcbcomp13svn &&
            tcb.sgxtcbcomp14svn <= sgx_extensions.tcb.sgxtcbcomp14svn &&
            tcb.sgxtcbcomp15svn <= sgx_extensions.tcb.sgxtcbcomp15svn &&
            tcb.sgxtcbcomp16svn <= sgx_extensions.tcb.sgxtcbcomp16svn &&
            tcb.pcesvn <= sgx_extensions.tcb.pcesvn {
                // println!("tcb_status: {:?}", tcb_level.tcb_status);
                return match tcb_level.tcb_status.as_str() {
                    "UpToDate" => TcbStatus::OK,
                    "SWHardeningNeeded" => TcbStatus::TcbSwHardeningNeeded,
                    "ConfigurationAndSWHardeningNeeded" => TcbStatus::TcbConfigurationAndSwHardeningNeeded,
                    "ConfigurationNeeded" => TcbStatus::TcbConfigurationNeeded,
                    "OutOfDate" => TcbStatus::TcbOutOfDate,
                    "OutOfDateConfigurationNeeded" => TcbStatus::TcbOutOfDateConfigurationNeeded,
                    "Revoked" => TcbStatus::TcbRevoked,
                    _ => TcbStatus::TcbUnrecognized,
                }
        }
    }
    // we went through all the tcblevels and didn't find a match
    // shouldn't happen so we'll toggle an exception
    unreachable!();
}
