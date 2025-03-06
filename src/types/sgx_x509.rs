use std::collections::HashMap;
use std::fmt::Formatter;

use anyhow::{anyhow, Context, Error, Result};
use asn1::{oid, ObjectIdentifier, SequenceOf};

pub const SGX_EXTENSIONS_OID: &str = "1.2.840.113741.1.13.1";
const _SGX_EXTENSIONS_OID_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1);
const PPID_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 1);

const TCB_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2);
const TCB_COMP01SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 1);
const TCB_COMP02SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 2);
const TCB_COMP03SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 3);
const TCB_COMP04SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 4);
const TCB_COMP05SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 5);
const TCB_COMP06SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 6);
const TCB_COMP07SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 7);
const TCB_COMP08SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 8);
const TCB_COMP09SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 9);
const TCB_COMP10SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 10);
const TCB_COMP11SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 11);
const TCB_COMP12SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 12);
const TCB_COMP13SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 13);
const TCB_COMP14SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 14);
const TCB_COMP15SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 15);
const TCB_COMP16SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 16);
const TCB_PCESVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 17);
const TCB_CPUSVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 18);

const PCE_ID_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 3);
const FMSPC_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 4);
const SGX_TYPE_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 5);
//const PLATFORM_INSTANCE_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 6);

//const CONFIGURATION_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 7);
const CONFIGURATION_DYNAMIC_PLATFORM_OID: ObjectIdentifier =
    oid!(1, 2, 840, 113741, 1, 13, 1, 7, 1);
const CONFIGURATION_CACHED_KEYS_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 7, 2);
const CONFIGURATION_SMT_ENABLED_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 7, 3);

const PPID_LEN: usize = 16;
const CPUSVN_LEN: usize = 16;
const PCEID_LEN: usize = 2;
const FMSPC_LEN: usize = 6;
//const PLATFORM_INSTANCE_ID_LEN: usize = 16;
const COMPSVN_LEN: usize = 16;
