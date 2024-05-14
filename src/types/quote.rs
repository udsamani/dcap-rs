// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf

// high level sgx quote structure
// [48 - header] [384 - isv enclave report] [4 - quote signature length] [var - quote signature] 
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SgxQuoteV3 {
    pub header: SgxQuoteHeaderV3,               // [48 bytes]
                                                // Header of Quote data structure. This field is transparent (the user knows
                                                // its internal structure). Rest of the Quote data structure can be
                                                // treated as opaque (hidden from the user).
    pub isv_enclave_report: SgxEnclaveReport,   // [384 bytes]
                                                // Report of the attested ISV Enclave.
                                                // The CPUSVN and ISVSVN is the TCB when the quote is generated.
                                                // The REPORT.ReportData is defined by the ISV but should provide quote replay 
                                                // protection if required.
    pub signature_len: u32,                     // [4 bytes]
                                                // Size of the Quote Signature Data structure in bytes.
    pub signature: Vec<u8>,                     // [variable bytes]
                                                // Variable-length data containing the signature and supporting data. 
                                                // E.g. ECDSA 256-bit Quote Signature Data Structure (SgxQuoteSignatureData)
}

impl SgxQuoteV3 {
    pub fn from_bytes(raw_bytes: &[u8]) -> SgxQuoteV3 {
        let header = SgxQuoteHeaderV3::from_bytes(&raw_bytes[0..48]);
        let isv_enclave_report = SgxEnclaveReport::from_bytes(&raw_bytes[48..432]);
        let signature_len = u32::from_le_bytes([raw_bytes[432], raw_bytes[433], raw_bytes[434], raw_bytes[435]]);
        // allocate and create a buffer for signature
        let signature_slice = &raw_bytes[436..];
        assert_eq!(signature_slice.len(), signature_len as usize);
        let signature = signature_slice.to_vec();

        SgxQuoteV3 {
            header,
            isv_enclave_report,
            signature_len,
            signature,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SgxQuoteHeaderV3 {
    pub version: u16,           // [2 bytes]
                                // version of the quote data structure - 3
    pub att_key_type: u16,      // [2 bytes] 
                                // Type of the Attestation Key used by the Quoting Enclave - 2 (ECDSA-256-with-P-256 curve)
    pub reserved: [u8; 4],      // [4 bytes] 
                                // Reserved for future use - 0
    pub qe_svn: u16,            // [2 bytes]
                                // Security Version of the Quoting Enclave - 1
    pub pce_svn: u16,           // [2 bytes] 
                                // Security Version of the PCE - 0
    pub qe_vendor_id: [u8; 16], // [16 bytes] 
                                // Unique identifier of the QE Vendor. 
                                // Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
    pub user_data: [u8; 20],    // [20 bytes] 
                                // Custom user-defined data. 
                                // For the Intel® SGX DCAP library, the first 16 bytes contain a QE identifier that is 
                                // used to link a PCK Cert to an Enc(PPID). This identifier is consistent for
                                // every quote generated with this QE on this platform.
}

impl SgxQuoteHeaderV3 {
    pub fn from_bytes(raw_bytes: &[u8]) -> SgxQuoteHeaderV3 {
        assert_eq!(raw_bytes.len(), 48);

        let version = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
        let att_key_type = u16::from_le_bytes([raw_bytes[2], raw_bytes[3]]);
        let mut reserved = [0; 4];
        reserved.copy_from_slice(&raw_bytes[4..8]);
        let qe_svn = u16::from_le_bytes([raw_bytes[8], raw_bytes[9]]);
        let pce_svn = u16::from_le_bytes([raw_bytes[10], raw_bytes[11]]);
        let mut qe_vendor_id = [0; 16];
        qe_vendor_id.copy_from_slice(&raw_bytes[12..28]);
        let mut user_data = [0; 20];
        user_data.copy_from_slice(&raw_bytes[28..48]);

        SgxQuoteHeaderV3 {
            version,
            att_key_type,
            reserved,
            qe_svn,
            pce_svn,
            qe_vendor_id,
            user_data,
        }
    }

    pub fn to_bytes(self) -> [u8; 48] {
        let mut raw_bytes = [0; 48];
        raw_bytes[0..2].copy_from_slice(&self.version.to_le_bytes());
        raw_bytes[2..4].copy_from_slice(&self.att_key_type.to_le_bytes());
        raw_bytes[4..8].copy_from_slice(&self.reserved);
        raw_bytes[8..10].copy_from_slice(&self.qe_svn.to_le_bytes());
        raw_bytes[10..12].copy_from_slice(&self.pce_svn.to_le_bytes());
        raw_bytes[12..28].copy_from_slice(&self.qe_vendor_id);
        raw_bytes[28..48].copy_from_slice(&self.user_data);

        raw_bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SgxEnclaveReport {
    pub cpu_svn: [u8; 16],      // [16 bytes]
                                // Security Version of the CPU (raw value)
    pub misc_select: [u8; 4],   // [4 bytes]
                                // SSA Frame extended feature set. 
                                // Reports what SECS.MISCSELECT settings are used in the enclave. You can limit the
                                // allowed MISCSELECT settings in the sigstruct using MISCSELECT/MISCMASK.
    pub reserved_1: [u8; 28],   // [28 bytes]
                                // Reserved for future use - 0
    pub attributes: [u8; 16],   // [16 bytes]
                                // Set of flags describing attributes of the enclave.
                                // Reports what SECS.ATTRIBUTES settings are used in the enclave. The ISV can limit what
                                // SECS.ATTRIBUTES can be used when loading the enclave through parameters to the SGX Signtool.
                                // The Signtool will produce a SIGSTRUCT with ATTRIBUTES and ATTRIBUTESMASK 
                                // which determine allowed ATTRIBUTES.
                                // - For each SIGSTRUCT.ATTRIBUTESMASK bit that is set, then corresponding bit in the
                                // SECS.ATTRIBUTES must match the same bit in SIGSTRUCT.ATTRIBUTES.
    pub mrenclave: [u8; 32],    // [32 bytes] 
                                // Measurement of the enclave. 
                                // The MRENCLAVE value is the SHA256 hash of the ENCLAVEHASH field in the SIGSTRUCT.
    pub reserved_2: [u8; 32],   // [32 bytes] 
                                // Reserved for future use - 0
    pub mrsigner: [u8; 32],     // [32 bytes]
                                // Measurement of the enclave signer. 
                                // The MRSIGNER value is the SHA256 hash of the MODULUS field in the SIGSTRUCT.
    pub reserved_3: [u8; 96],   // [96 bytes]
                                // Reserved for future use - 0
    pub isv_prod_id: u16,       // [2 bytes]
                                // Product ID of the enclave. 
                                // The ISV should configure a unique ISVProdID for each product which may
                                // want to share sealed data between enclaves signed with a specific MRSIGNER. The ISV
                                // may want to supply different data to identical enclaves signed for different products.
    pub isv_svn: u16,           // [2 bytes]
                                // Security Version of the enclave
    pub reserved_4: [u8; 60],   // [60 bytes]
                                // Reserved for future use - 0
    pub report_data: [u8; 64],  // [64 bytes]
                                // Additional report data.
                                // The enclave is free to provide 64 bytes of custom data to the REPORT.
                                // This can be used to provide specific data from the enclave or it can be used to hold 
                                // a hash of a larger block of data which is provided with the quote. 
                                // The verification of the quote signature confirms the integrity of the
                                // report data (and the rest of the REPORT body).
}

impl SgxEnclaveReport {
    pub fn from_bytes(raw_bytes: &[u8]) -> SgxEnclaveReport{
        assert_eq!(raw_bytes.len(), 384);
        let mut obj = SgxEnclaveReport {
            cpu_svn: [0; 16],
            misc_select: [0; 4],
            reserved_1: [0; 28],
            attributes: [0; 16],
            mrenclave: [0; 32],
            reserved_2: [0; 32],
            mrsigner: [0; 32],
            reserved_3: [0; 96],
            isv_prod_id: 0,
            isv_svn: 0,
            reserved_4: [0; 60],
            report_data: [0; 64],
        };

        // parse raw bytes into obj
        obj.cpu_svn.copy_from_slice(&raw_bytes[0..16]);
        obj.misc_select.copy_from_slice(&raw_bytes[16..20]);
        obj.reserved_1.copy_from_slice(&raw_bytes[20..48]);
        obj.attributes.copy_from_slice(&raw_bytes[48..64]);
        obj.mrenclave.copy_from_slice(&raw_bytes[64..96]);
        obj.reserved_2.copy_from_slice(&raw_bytes[96..128]);
        obj.mrsigner.copy_from_slice(&raw_bytes[128..160]);
        obj.reserved_3.copy_from_slice(&raw_bytes[160..256]);
        obj.isv_prod_id = u16::from_le_bytes([raw_bytes[256], raw_bytes[257]]);
        obj.isv_svn = u16::from_le_bytes([raw_bytes[258], raw_bytes[259]]);
        obj.reserved_4.copy_from_slice(&raw_bytes[260..320]);
        obj.report_data.copy_from_slice(&raw_bytes[320..384]);

        return obj;
    }

    pub fn to_bytes(self) -> [u8; 384] {
        // convert the struct into raw bytes
        let mut raw_bytes = [0; 384];
        // copy the fields into the raw bytes
        raw_bytes[0..16].copy_from_slice(&self.cpu_svn);
        raw_bytes[16..20].copy_from_slice(&self.misc_select);
        raw_bytes[20..48].copy_from_slice(&self.reserved_1);
        raw_bytes[48..64].copy_from_slice(&self.attributes);
        raw_bytes[64..96].copy_from_slice(&self.mrenclave);
        raw_bytes[96..128].copy_from_slice(&self.reserved_2);
        raw_bytes[128..160].copy_from_slice(&self.mrsigner);
        raw_bytes[160..256].copy_from_slice(&self.reserved_3);
        raw_bytes[256..258].copy_from_slice(&self.isv_prod_id.to_le_bytes());
        raw_bytes[258..260].copy_from_slice(&self.isv_svn.to_le_bytes());
        raw_bytes[260..320].copy_from_slice(&self.reserved_4);
        raw_bytes[320..384].copy_from_slice(&self.report_data);

        raw_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SgxQuoteSignatureDataV3 {
    pub isv_enclave_report_signature: [u8; 64],     // ECDSA signature, the r component followed by the s component, 2 x 32 bytes.
    pub ecdsa_attestation_key: [u8; 64],            // EC KT-I Public Key, the x-coordinate followed by the y-coordinate 
                                                    // (on the RFC 6090 P-256 curve), 2 x 32 bytes.
    pub qe_report: SgxEnclaveReport,
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: SgxQeAuthDataV3,
    pub qe_cert_data: SgxQeCertDataV3,
}

impl SgxQuoteSignatureDataV3 {
    pub fn from_bytes(raw_bytes: &[u8]) -> SgxQuoteSignatureDataV3 {
        let mut isv_enclave_report_signature = [0u8; 64];
        let mut ecdsa_attestation_key = [0u8; 64];
        let mut qe_report_signature = [0u8; 64];

        isv_enclave_report_signature.copy_from_slice(&raw_bytes[0..64]);
        ecdsa_attestation_key.copy_from_slice(&raw_bytes[64..128]);
        let qe_report = SgxEnclaveReport::from_bytes(&raw_bytes[128..512]);
        qe_report_signature.copy_from_slice(&raw_bytes[512..576]);
        let qe_auth_data = SgxQeAuthDataV3::from_bytes(&raw_bytes[576..]);
        let qe_cert_data_start = 576 + 2 + qe_auth_data.size as usize;
        let qe_cert_data = SgxQeCertDataV3::from_bytes(&raw_bytes[qe_cert_data_start..]);

        SgxQuoteSignatureDataV3 {
            isv_enclave_report_signature,
            ecdsa_attestation_key,
            qe_report,
            qe_report_signature,
            qe_auth_data,
            qe_cert_data,
        }
    }
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SgxQeAuthDataV3 {
    pub size: u16,
    pub data: Vec<u8>,
}

impl SgxQeAuthDataV3 {
    pub fn from_bytes(raw_bytes: &[u8]) -> SgxQeAuthDataV3 {
        let size = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
        let data = raw_bytes[2..2+size as usize].to_vec();
        SgxQeAuthDataV3 {
            size,
            data,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SgxQeCertDataV3 {
    pub cert_data_type: u16,
    pub cert_data_size: u32,
    pub cert_data: Vec<u8>,
}

impl SgxQeCertDataV3 {
    pub fn from_bytes(raw_bytes: &[u8]) -> SgxQeCertDataV3 {
        let cert_data_type = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
        let cert_data_size = u32::from_le_bytes([raw_bytes[2], raw_bytes[3], raw_bytes[4], raw_bytes[5]]);
        let cert_data = raw_bytes[6..6+cert_data_size as usize].to_vec();
        SgxQeCertDataV3 {
            cert_data_type,
            cert_data_size,
            cert_data
        }
    }
}

#[derive(Clone, Debug)]
pub struct QuoteV4 {
    pub header: QuoteHeader,            // [48 bytes]
                                        // Header of Quote data structure.
                                        // This field is transparent (the user knows its internal structure).
                                        // Rest of the Quote data structure can be treated as opaque (hidden from the user).
    pub quote_body: QuoteBodyV4,        // [584 bytes]
                                        // Report of the attested TD. 
                                        // The REPORTDATA contained in this field is defined by the TD developer. 
                                        // See the description of the field for example usages.
    pub signature_len: u32,             // [4 bytes]
                                        // Size of the Quote Signature Data structure in bytes.
    pub signature: Vec<u8>,             // [variable bytes]
}

impl QuoteV4 {
    pub fn from_bytes(raw_bytes: &[u8]) -> Self {
        let header = QuoteHeader::from_bytes(&raw_bytes[0..48]);
        let quote_body = QuoteBodyV4::from_bytes(&raw_bytes[48..632]);
        let signature_len = u32::from_le_bytes([raw_bytes[632], raw_bytes[633], raw_bytes[634], raw_bytes[635]]);
        let signature_slice = &raw_bytes[636..636+signature_len as usize];
        let signature = signature_slice.to_vec();

        QuoteV4 {
            header,
            quote_body,
            signature_len,
            signature,
        }
    }
}

#[derive(Clone, Debug)]
pub struct QuoteHeader {
    pub version: u16,                   // [2 bytes]
                                        // Version of the quote data structure - 4, 5
    pub att_key_type: u16,              // [2 bytes]
                                        // Type of the Attestation Key used by the Quoting Enclave -
                                        // 2 (ECDSA-256-with-P-256 curve) 
                                        // 3 (ECDSA-384-with-P-384 curve)
    pub tee_type: u32,                  // [4 bytes]
                                        // TEE for this Attestation
                                        // 0x00000000: SGX
                                        // 0x00000081: TDX
    pub reserved_1: [u8; 2],            // [2 bytes]
                                        // Reserved for future use - 0
    pub reserved_2: [u8; 2],            // [2 bytes]
                                        // Reserved for future use - 0
    pub qe_vendor_id: [u8; 16],         // [16 bytes]
                                        // Unique identifier of the QE Vendor. 
                                        // Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
                                        // Note: Each vendor that decides to provide a customized Quote data structure should have
                                        // unique ID.
    pub user_data: [u8; 20],            // [20 bytes]
                                        // Custom user-defined data. For the Intel® SGX and TDX DCAP Quote Generation Libraries, 
                                        // the first 16 bytes contain a Platform Identifier that is used to link a PCK Certificate to an Enc(PPID).
}

impl QuoteHeader {
    pub fn from_bytes(raw_bytes: &[u8]) -> Self {
        let version = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
        let att_key_type = u16::from_le_bytes([raw_bytes[2], raw_bytes[3]]);
        let tee_type = u32::from_le_bytes([raw_bytes[4], raw_bytes[5], raw_bytes[6], raw_bytes[7]]);
        let mut reserved_1 = [0; 2];
        reserved_1.copy_from_slice(&raw_bytes[8..10]);
        let mut reserved_2 = [0; 2];
        reserved_2.copy_from_slice(&raw_bytes[10..12]);
        let mut qe_vendor_id = [0; 16];
        qe_vendor_id.copy_from_slice(&raw_bytes[12..28]);
        let mut user_data = [0; 20];
        user_data.copy_from_slice(&raw_bytes[28..48]);

        QuoteHeader {
            version,
            att_key_type,
            tee_type,
            reserved_1,
            reserved_2,
            qe_vendor_id,
            user_data,
        }
    }
}

// TD Attributes:
// [bits]   : [description]
// [0:7]    : (TUD) TD Under Debug flags. 
//            If any of the bits in this group are set to 1, the TD is untrusted.
//            [0]     - (DEBUG) Defines whether the TD runs in TD debug mode (set to 1) or not (set to 0). 
//                      In TD debug mode, the CPU state and private memory are accessible by the host VMM.
//            [1:7]   - (RESERVED) Reserved for future TUD flags, must be 0.
// [8:31]   : (SEC) Attributes that may impact the security of the TD
//            [8:27]  - (RESERVED) Reserved for future SEC flags, must be 0.
//            [28]    - (SEPT_VE_DISABLE) Disable EPT violation conversion to #VE on TD access of PENDING pages
//            [29]    - (RESERVED) Reserved for future SEC flags, must be 0.
//            [30]    - (PKS) TD is allowed to use Supervisor Protection Keys.
//            [31]    - (KL) TD is allowed to use Key Locker.
// [32:63]  : (OTHER) Attributes that do not impact the security of the TD
//            [32:62] - (RESERVED) Reserved for future OTHER flags, must be 0.
//            [63]    - (PERFMON) TD is allowed to use Perfmon and PERF_METRICS capabilities.

// TEE_TCB_SVN:
// [bytes]  : [Name]            : [description]
// [0]      : Tdxtcbcomp01      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[0]
// [1]      : Tdxtcbcomp02      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[1]
// [2]      : Tdxtcbcomp03      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[2
// [3]      : Tdxtcbcomp04      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[3]
// [4]      : Tdxtcbcomp05      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[4]
// [5]      : Tdxtcbcomp06      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[5]
// [6]      : Tdxtcbcomp07      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[6]
// [7]      : Tdxtcbcomp08      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[7]
// [8]      : Tdxtcbcomp09      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[8]
// [9]      : Tdxtcbcomp10      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[9]
// [10]     : Tdxtcbcomp11      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[10]
// [11]     : Tdxtcbcomp12      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[11]
// [12]     : Tdxtcbcomp13      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[12]
// [13]     : Tdxtcbcomp14      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[13]
// [14]     : Tdxtcbcomp15      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[14]
// [15]     : Tdxtcbcomp16      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[15]

#[derive(Clone, Debug)]
pub struct QuoteBodyV4 {
    pub tee_tcb_svn: [u8; 16],          // [16 bytes]
                                        // Describes the TCB of TDX. (Refer to above)
    pub mrseam: [u8; 48],               // [48 bytes]
                                        // Measurement of the TDX Module.
    pub mrsignerseam: [u8; 48],         // [48 bytes]
                                        // Zero for Intel TDX Module
    pub seam_attributes: u64,           // [8 bytes]
                                        // Must be zero for TDX 1.0
    pub td_attributes: u64,             // [8 bytes]
                                        // TD Attributes (Refer to above)
    pub xfam: u64,                      // [8 bytes]
                                        // XFAM (eXtended Features Available Mask) is defined as a 64b bitmap, which has the same format as XCR0 or IA32_XSS MSR.
    pub mrtd: [u8; 48],                 // [48 bytes]
                                        // (SHA384) Measurement of the initial contents of the TD.
    pub mrconfigid: [u8; 48],           // [48 bytes]
                                        // Software-defined ID for non-owner-defined configuration of the TD, e.g., runtime or OS configuration.
    pub mrowner: [u8; 48],              // [48 bytes]
                                        // Software-defined ID for the TD’s owner
    pub mrownerconfig: [u8; 48],        // [48 bytes]
                                        // Software-defined ID for owner-defined configuration of the TD, 
                                        // e.g., specific to the workload rather than the runtime or OS.
    pub rtmr0: [u8; 48],                // [48 bytes]
                                        // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr1: [u8; 48],                // [48 bytes]
                                        // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr2: [u8; 48],                // [48 bytes]
                                        // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr3: [u8; 48],                // [48 bytes]
                                        // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub report_data: [u8; 64],          // [64 bytes]
                                        // Additional report data.
                                        // The TD is free to provide 64 bytes of custom data to the REPORT.
                                        // This can be used to provide specific data from the TD or it can be used to hold a hash of a larger block of data which is provided with the quote.
                                        // Note that the signature of a TD Quote covers the REPORTDATA field. As a result, the integrity is protected with a key rooted in an Intel CA.
}

impl QuoteBodyV4 {
    pub fn from_bytes(raw_bytes: &[u8]) -> Self {
        // copy the bytes into the struct
        let mut tee_tcb_svn = [0; 16];
        tee_tcb_svn.copy_from_slice(&raw_bytes[0..16]);
        let mut mrseam = [0; 48];
        mrseam.copy_from_slice(&raw_bytes[16..64]);
        let mut mrsignerseam = [0; 48];
        mrsignerseam.copy_from_slice(&raw_bytes[64..112]);
        let seam_attributes = u64::from_le_bytes([raw_bytes[112], raw_bytes[113], raw_bytes[114], raw_bytes[115], raw_bytes[116], raw_bytes[117], raw_bytes[118], raw_bytes[119]]);
        let td_attributes = u64::from_le_bytes([raw_bytes[120], raw_bytes[121], raw_bytes[122], raw_bytes[123], raw_bytes[124], raw_bytes[125], raw_bytes[126], raw_bytes[127]]);
        let xfam = u64::from_le_bytes([raw_bytes[128], raw_bytes[129], raw_bytes[130], raw_bytes[131], raw_bytes[132], raw_bytes[133], raw_bytes[134], raw_bytes[135]]);
        let mut mrtd = [0; 48];
        mrtd.copy_from_slice(&raw_bytes[136..184]);
        let mut mrconfigid = [0; 48];
        mrconfigid.copy_from_slice(&raw_bytes[184..232]);
        let mut mrowner = [0; 48];
        mrowner.copy_from_slice(&raw_bytes[232..280]);
        let mut mrownerconfig = [0; 48];
        mrownerconfig.copy_from_slice(&raw_bytes[280..328]);
        let mut rtmr0 = [0; 48];
        rtmr0.copy_from_slice(&raw_bytes[328..376]);
        let mut rtmr1 = [0; 48];
        rtmr1.copy_from_slice(&raw_bytes[376..424]);
        let mut rtmr2 = [0; 48];
        rtmr2.copy_from_slice(&raw_bytes[424..472]);
        let mut rtmr3 = [0; 48];
        rtmr3.copy_from_slice(&raw_bytes[472..520]);
        let mut report_data = [0; 64];
        report_data.copy_from_slice(&raw_bytes[520..584]);

        QuoteBodyV4 {
            tee_tcb_svn,
            mrseam,
            mrsignerseam,
            seam_attributes,
            td_attributes,
            xfam,
            mrtd,
            mrconfigid,
            mrowner,
            mrownerconfig,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            report_data,
        }
    }
}

#[derive(Clone, Debug)]
pub struct QuoteSignatureDataV4 {
    pub quote_signature: [u8; 64],      // [64 bytes]
                                        // ECDSA signature, the r component followed by the s component, 2 x 32 bytes.
                                        // Public part of the Attestation Key generated by the Quoting Enclave.
    pub ecdsa_attestation_key: [u8; 64],// [64 bytes]
                                        // EC KT-I Public Key, the x-coordinate followed by the y-coordinate (on the RFC 6090 P-256 curve), 2 x 32 bytes.
                                        // Public part of the Attestation Key generated by the Quoting Enclave.
    pub qe_cert_data: QeCertDataV4,     // [variable bytes]
                                        // QE Cert Data
}

impl QuoteSignatureDataV4 {
    pub fn from_bytes(raw_bytes: &[u8]) -> Self {
        let mut quote_signature = [0; 64];
        quote_signature.copy_from_slice(&raw_bytes[0..64]);
        let mut ecdsa_attestation_key = [0; 64];
        ecdsa_attestation_key.copy_from_slice(&raw_bytes[64..128]);
        let qe_cert_data = QeCertDataV4::from_bytes(&raw_bytes[128..]);

        QuoteSignatureDataV4 {
            quote_signature,
            ecdsa_attestation_key,
            qe_cert_data,
        }
    }
}

#[derive(Clone, Debug)]
pub struct QeCertDataV4 {
    pub cert_data_type: u16,            // [2 bytes]
                                        // Determines type of data required to verify the QE Report Signature in the Quote Signature Data structure. 
                                        // 1 - (PCK identifier: PPID in plain text, CPUSVN, and PCESVN)
                                        // 2 - (PCK identifier: PPID encrypted using RSA-2048-OAEP, CPUSVN, and PCESVN)
                                        // 3 - (PCK identifier: PPID encrypted using RSA-2048-OAEP, CPUSVN, PCESVN, and QEID)
                                        // 4 - (PCK Leaf Certificate in plain text; currently not supported)
                                        // 5 - (Concatenated PCK Cert Chain)
                                        // 6 - (QE Report Certification Data)
                                        // 7 - (PLATFORM_MANIFEST; currently not supported)
    pub cert_data_size: u32,            // [4 bytes]
                                        // Size of Certification Data field.
    pub cert_data: Vec<u8>,             // [variable bytes]
                                        // Data required to verify the QE Report Signature depending on the value of the Certification Data Type:
                                        // 1: Byte array that contains concatenation of PPID, CPUSVN, PCESVN (LE), PCEID (LE).
                                        // 2: Byte array that contains concatenation of PPID encrypted using RSA-2048-OAEP, CPUSVN, PCESVN (LE), PCEID (LE).
                                        // 3: Byte array that contains concatenation of PPID encrypted using RSA-3072-OAEP, CPUSVN, PCESVN (LE), PCEID (LE).
                                        // 4: PCK Leaf Certificate
                                        // 5: Concatenated PCK Cert Chain (PEM formatted). PCK Leaf Cert || Intermediate CA Cert || Root CA Cert 
                                        // 6: QE Report Certification Data
                                        // 7: PLATFORM_MANIFEST
}

impl QeCertDataV4 {
    pub fn from_bytes(raw_bytes: &[u8]) -> Self {
        let cert_data_type = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
        let cert_data_size = u32::from_le_bytes([raw_bytes[2], raw_bytes[3], raw_bytes[4], raw_bytes[5]]);
        let cert_data = raw_bytes[6..6+cert_data_size as usize].to_vec();

        QeCertDataV4 {
            cert_data_type,
            cert_data_size,
            cert_data,
        }
    }
}