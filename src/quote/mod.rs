mod quote {
    // https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf

    // high level sgx quote structure
    // [48 - header] [384 - isv enclave report] [4 - quote signature length] [var - quote signature] 

    struct SgxQuote {
        header: SgxQuoteHeader,                 // 48 bytes
                                                // Header of Quote data structure. This field is transparent (the user knows
                                                // its internal structure). Rest of the Quote data structure can be
                                                // treated as opaque (hidden from the user).
        isv_enclave_report: SgxEnclaveReport,   // 384 bytes
                                                // Report of the attested ISV Enclave.
                                                // The CPUSVN and ISVSVN is the TCB when the quote is generated.
                                                // The REPORT.ReportData is defined by the ISV but should provide quote replay 
                                                // protection if required.
        signature_len: u32,                     // 4 bytes
                                                // Size of the Quote Signature Data structure in bytes.
        signature: Vec<u8>,                     // variable bytes
                                                // Variable-length data containing the signature and supporting data. 
                                                // E.g. ECDSA 256-bit Quote Signature Data Structure (SgxEnclaveReport)
    }

    struct SgxQuoteHeader {
        version: u16,           // version of the quote data structure - 3
        att_key_type: u16,      // Type of the Attestation Key used by the Quoting Enclave - 2 (ECDSA-256-with-P-256 curve)
        reserved: u16,          // Reserved for future use - 0
        qe_svn: u16,            // Security Version of the Quoting Enclave - 1
        pce_svn: u16,           // Security Version of the PCE - 0
        qe_vendor_id: [u8; 16], // Unique identifier of the QE Vendor. 
                                // Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
        user_data: [u8; 20],    // Custom user-defined data. 
                                // For the Intel® SGX DCAP library, the first 16 bytes contain a QE identifier that is 
                                // used to link a PCK Cert to an Enc(PPID). This identifier is consistent for
                                //every quote generated with this QE on this platform.
        
    }

    struct SgxEnclaveReport {
        cpu_svn: [u8; 16],      // Security Version of the CPU (raw value)
        misc_select: [u8; 4],   // SSA Frame extended feature set. 
                                // Reports what SECS.MISCSELECT settings are used in the enclave. You can limit the
                                // allowed MISCSELECT settings in the sigstruct using MISCSELECT/MISCMASK.
        reserved_1: [u8; 28],   // Reserved for future use - 0
        attributes: [u8; 16],   // Set of flags describing attributes of the enclave.
                                // Reports what SECS.ATTRIBUTES settings are used in the enclave. The ISV can limit what
                                // SECS.ATTRIBUTES can be used when loading the enclave through parameters to the SGX Signtool.
                                // The Signtool will produce a SIGSTRUCT with ATTRIBUTES and ATTRIBUTESMASK 
                                // which determine allowed ATTRIBUTES.
                                // - For each SIGSTRUCT.ATTRIBUTESMASK bit that is set, then corresponding bit in the
                                // SECS.ATTRIBUTES must match the same bit in SIGSTRUCT.ATTRIBUTES.
        mrenclave: [u8; 32],    // Measurement of the enclave. 
                                // The MRENCLAVE value is the SHA256 hash of the ENCLAVEHASH field in the SIGSTRUCT.
        reserved_2: [u8; 32],   // Reserved for future use - 0
        mrsigner: [u8; 32],     // Measurement of the enclave signer. 
                                // The MRSIGNER value is the SHA256 hash of the MODULUS field in the SIGSTRUCT.
        reserved_3: [u8; 96],   // Reserved for future use - 0
        isv_prod_id: u16,       // Product ID of the enclave. 
                                // The ISV should configure a unique ISVProdID for each product which may
                                // want to share sealed data between enclaves signed with a specific MRSIGNER. The ISV
                                // may want to supply different data to identical enclaves signed for different products.
        isv_svn: u16,           // Security Version of the enclave
        reserved_4: [u8; 60],   // Reserved for future use - 0
        report_data: [u8; 64],  // Additional report data.
                                // The enclave is free to provide 64 bytes of custom data to the REPORT.
                                // This can be used to provide specific data from the enclave or it can be used to hold 
                                // a hash of a larger block of data which is provided with the quote. 
                                // The verification of the quote signature confirms the integrity of the
                                // report data (and the rest of the REPORT body).
    }
}