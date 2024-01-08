mod quote {
    // https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf

    // high level sgx quote structure
    // [48 - header] [384 - isv enclave report] [4 - quote signature length] [var - quote signature] 

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SgxQuote {
        header: SgxQuoteHeader,                 // [48 bytes]
                                                // Header of Quote data structure. This field is transparent (the user knows
                                                // its internal structure). Rest of the Quote data structure can be
                                                // treated as opaque (hidden from the user).
        isv_enclave_report: SgxEnclaveReport,   // [384 bytes]
                                                // Report of the attested ISV Enclave.
                                                // The CPUSVN and ISVSVN is the TCB when the quote is generated.
                                                // The REPORT.ReportData is defined by the ISV but should provide quote replay 
                                                // protection if required.
        signature_len: u32,                     // [4 bytes]
                                                // Size of the Quote Signature Data structure in bytes.
        signature: *mut u8,                     // [variable bytes]
                                                // Variable-length data containing the signature and supporting data. 
                                                // E.g. ECDSA 256-bit Quote Signature Data Structure (SgxEnclaveReport)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SgxQuoteHeader {
        version: u16,           // [2 bytes]
                                // version of the quote data structure - 3
        att_key_type: u16,      // [2 bytes] 
                                // Type of the Attestation Key used by the Quoting Enclave - 2 (ECDSA-256-with-P-256 curve)
        reserved: [u8; 4],      // [4 bytes] 
                                // Reserved for future use - 0
        qe_svn: u16,            // [2 bytes]
                                // Security Version of the Quoting Enclave - 1
        pce_svn: u16,           // [2 bytes] 
                                // Security Version of the PCE - 0
        qe_vendor_id: [u8; 16], // [16 bytes] 
                                // Unique identifier of the QE Vendor. 
                                // Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
        user_data: [u8; 20],    // [20 bytes] 
                                // Custom user-defined data. 
                                // For the Intel® SGX DCAP library, the first 16 bytes contain a QE identifier that is 
                                // used to link a PCK Cert to an Enc(PPID). This identifier is consistent for
                                //every quote generated with this QE on this platform.
        
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SgxEnclaveReport {
        cpu_svn: [u8; 16],      // [16 bytes]
                                // Security Version of the CPU (raw value)
        misc_select: [u8; 4],   // [4 bytes]
                                // SSA Frame extended feature set. 
                                // Reports what SECS.MISCSELECT settings are used in the enclave. You can limit the
                                // allowed MISCSELECT settings in the sigstruct using MISCSELECT/MISCMASK.
        reserved_1: [u8; 28],   // [28 bytes]
                                // Reserved for future use - 0
        attributes: [u8; 16],   // [16 bytes]
                                // Set of flags describing attributes of the enclave.
                                // Reports what SECS.ATTRIBUTES settings are used in the enclave. The ISV can limit what
                                // SECS.ATTRIBUTES can be used when loading the enclave through parameters to the SGX Signtool.
                                // The Signtool will produce a SIGSTRUCT with ATTRIBUTES and ATTRIBUTESMASK 
                                // which determine allowed ATTRIBUTES.
                                // - For each SIGSTRUCT.ATTRIBUTESMASK bit that is set, then corresponding bit in the
                                // SECS.ATTRIBUTES must match the same bit in SIGSTRUCT.ATTRIBUTES.
        mrenclave: [u8; 32],    // [32 bytes] 
                                // Measurement of the enclave. 
                                // The MRENCLAVE value is the SHA256 hash of the ENCLAVEHASH field in the SIGSTRUCT.
        reserved_2: [u8; 32],   // [32 bytes] 
                                // Reserved for future use - 0
        mrsigner: [u8; 32],     // [32 bytes]
                                // Measurement of the enclave signer. 
                                // The MRSIGNER value is the SHA256 hash of the MODULUS field in the SIGSTRUCT.
        reserved_3: [u8; 96],   // [96 bytes]
                                // Reserved for future use - 0
        isv_prod_id: u16,       // [2 bytes]
                                // Product ID of the enclave. 
                                // The ISV should configure a unique ISVProdID for each product which may
                                // want to share sealed data between enclaves signed with a specific MRSIGNER. The ISV
                                // may want to supply different data to identical enclaves signed for different products.
        isv_svn: u16,           // [2 bytes]
                                // Security Version of the enclave
        reserved_4: [u8; 60],   // [60 bytes]
                                // Reserved for future use - 0
        report_data: [u8; 64],  // [64 bytes]
                                // Additional report data.
                                // The enclave is free to provide 64 bytes of custom data to the REPORT.
                                // This can be used to provide specific data from the enclave or it can be used to hold 
                                // a hash of a larger block of data which is provided with the quote. 
                                // The verification of the quote signature confirms the integrity of the
                                // report data (and the rest of the REPORT body).
    }

    impl SgxQuote {
        pub fn from_bytes(raw_bytes: &[u8]) -> SgxQuote {
            let header = SgxQuoteHeader::from_bytes(&raw_bytes[0..48]);
            let isv_enclave_report = SgxEnclaveReport::from_bytes(&raw_bytes[48..432]);
            let signature_len = u32::from_le_bytes([raw_bytes[432], raw_bytes[433], raw_bytes[434], raw_bytes[435]]);
            // allocate and create a buffer for signature
            let signature_slice = &raw_bytes[436..];
            assert_eq!(signature_slice.len(), signature_len as usize);
            let signature = signature_slice.to_vec().into_boxed_slice().as_mut_ptr();

            SgxQuote {
                header,
                isv_enclave_report,
                signature_len,
                signature,
            }
        }
    }

    impl SgxQuoteHeader {
        pub fn from_bytes(raw_bytes: &[u8]) -> SgxQuoteHeader {
            assert_eq!(raw_bytes.len(), 48);
            let mut obj = SgxQuoteHeader {
                version: 0,
                att_key_type: 0,
                reserved: [0; 4],
                qe_svn: 0,
                pce_svn: 0,
                qe_vendor_id: [0; 16],
                user_data: [0; 20],
            };

            // parse raw bytes into obj
            obj.version = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
            obj.att_key_type = u16::from_le_bytes([raw_bytes[2], raw_bytes[3]]);
            obj.reserved.copy_from_slice(&raw_bytes[4..8]);
            obj.qe_svn = u16::from_le_bytes([raw_bytes[8], raw_bytes[9]]);
            obj.pce_svn = u16::from_le_bytes([raw_bytes[10], raw_bytes[11]]);
            obj.qe_vendor_id.copy_from_slice(&raw_bytes[12..28]);
            obj.user_data.copy_from_slice(&raw_bytes[28..48]);

            return obj;
        }
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
    }
}