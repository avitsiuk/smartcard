export const DEF_128_KEY = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];
/** Default 16 byte (128 bits) test static keys used in SCP02/SCP03 */
export const DEF_STATIC_128_KEYS = {
    enc: DEF_128_KEY,
    mac: DEF_128_KEY,
    dek: DEF_128_KEY,
};

/** List of Ins bytes as defined in GlobalPlatformCard specifications (2.2.1/2.3.1)*/
export enum EIns {
    // only for SCP
    /** 0x2A */
    PERFORM_SECURITY_OP = 0x2a, // perform_security_op_even in iso
    /** 0x50 */
    INIT_UPDATE = 0x50, // no iso variant
    /** 0x7A */
    BEGIN_R_MAC = 0x7a, // no iso variant
    /** 0x68 */
    END_R_MAC = 0x78, // no iso variant

    /** 0x70 */
    MANAGE_CHANNEL = 0x70, // as in iso
    /** 0xA4 */
    SELECT = 0xA4, // as in iso
    /** 0xCA */
    GET_DATA = 0xca, // as in iso
    /** 0xD8 */
    PUT_KEY = 0xd8, // put_next_data_even in iso
    /** 0xE2 */
    STORE_DATA = 0xe2, // append_record in iso
    /** 0xE4 */
    DELETE = 0xe4, // delete_file in iso
    /** 0xE6 */
    INSTALL = 0xe6, // terminate_df in iso
    /** 0xE8 */
    LOAD = 0xe8, // terminate ef in iso
    /** 0xF0 */
    SET_STATUS = 0xf0, // no iso variant
    /** 0xF2 */
    GET_STATUS = 0xf2, // no iso variant
}

/** Hex: 0x2A864886FC6B */
export const GP_OID_STR = '1.2.840.114283';

export enum EPrivileges {
    // byte 1
    SecurityDomain,            // 1-------
    DAPVerification,           // 11-----0
    DelegatedManagement,       // 1-1-----
    CardLock,                  // ---1----
    CardTerminate,             // ----1---
    CardReset,                 // -----1--
    CVMManagement,             // ------1-
    MandatedDAPVerification,   // 11-----1
    // byte 2
    TrustedPath,               // 1-------
    AuthorizedManagement,      // -1------
    TokenManagement,           // --1-----
    GlobalDelete,              // ---1----
    GlobalLock,                // ----1---
    GlobalRegistry,            // -----1--
    FinalApplication,          // ------1-
    GlobalService,             // -------1
    // byte 3 (----XXXX = RFU)
    ReceiptGeneration,         // 1-------
    CipheredLoadFileDataBlock, // -1------
    ContactlessActivation,     // --1-----
    ContactlessSelfActivation, // ---1----
}

export enum ESecurityLevel {
    Authenticated,    // 10------
    AnyAuthenticated, // 01------
    CDecryption,      // ------1-
    CMac,             // -------1
    REncryption,      // --1-----
    RMac,             // ---1----
    NoSecurityLevel,  // 00000000
}



/** Executable Load File Life Cycle */
export enum ELifeCycleExecLoadFile {
    LOADED, // 00000001
}

/** Application Life Cycle  */
export enum ELifeCycleApp {
    INSTALLED,    // 00000011
    SELECTABLE,   // 00000111
    APP_SPECIFIC, // 0xxxx111
    LOCKED,       // 1-----11
}

/** Security Domain Life Cycle */
export enum ELifeCycleSD {
    INSTALLED,    // 00000011
    SELECTABLE,   // 00000111
    PERSONALIZED, // 00001111
    LOCKED,       // 1000--11
}

/** Card Life Cycle  */
export enum ELifeCycleCard {
    OP_READY,    // 00000001
    INITIALIZED, // 00000111
    SECURED,     // 00001111
    CARD_LOCKED, // 01111111
    TERMINATED,  // 11111111
}

/** Key Type */
export enum EKeyType {
    /** DES - mode (ECB/CBC) implicitly known */
    DES = 0x80,
    /** Pre-Shared Key for Transport Layer Security */
    TLS_PSK = 0x85,
    /** AES (16, 24, or 32 long keys) */
    AES = 0x88,
    /** HMAC-SHA1 – length of HMAC is implicitly known */
    HMAC_SHA1 = 0x90,
    /** HMAC-SHA1-160 – length of HMAC is 160 bits */
    HMAC_SHA1_160 = 0x91,
    /** RSA Public Key - public exponent e component (clear text) */
    RSA_PUB_EXP_CLEAR = 0xA0,
    /** RSA Public Key - modulus N component (clear text) */
    RSA_MOD_CLEAR = 0xA1,
    /** RSA Private Key - modulus N component */
    RSA_MOD = 0xA2,
    /** RSA Private Key - private exponent d component */
    RSA_PRIV_EXP = 0xA3,

    /** RSA Private Key - Chinese Remainder P component */
    RSA_CH_REM_P = 0xA4,
    /** RSA Private Key - Chinese Remainder Q component */
    RSA_CH_REM_Q = 0xA5,
    /** RSA Private Key - Chinese Remainder PQ component ( q-1 mod p ) */
    RSA_CH_REM_PQ = 0xA6,
    /** RSA Private Key - Chinese Remainder DP1 component ( d mod (p-1) ) */
    RSA_CH_REM_DP1 = 0xA7,
    /** RSA Private Key - Chinese Remainder DQ1 component ( d mod (q-1) ) */
    RSA_CH_REM_DQ1 = 0xA8,
    /** ECC public key (uncompressed) */
    ECC_PUB = 0xB0,
    /** ECC private key */
    ECC_PRIV = 0xB1,
    /** ECC field parameter P (field specification) */
    ECC_PARAM_P = 0xB2,
    /** ECC field parameter A (first coefficient) */
    ECC_PARAM_A = 0xB3,
    /** ECC field parameter B (second coefficient) */
    ECC_PARAM_B = 0xB4,
    /** ECC field parameter G (generator, uncompressed) */
    ECC_PARAM_G = 0xB5,
    /** ECC field parameter N (order of generator) */
    ECC_PARAM_N = 0xB6,
    /** ECC field parameter k (cofactor of order of generator) */
    ECC_PARAM_K = 0xB7,
    /** ECC key parameters reference */
    ECC_KEY_PARAM_REF = 0xF0,
    /** Extended format (usage defined for specific APDU commands; e.g. PUT KEY) */
    EXT = 0xFF,
}

export enum EKeyUsageQualifier {
    // first byte
    /** Verification (DST, CCT, CAT), Encipherment (CT) */
    VERIFY_ENC = 0x80,         // 1-------
    /** Computation (DST, CCT, CAT), Decipherment (CT) */
    COMPUTE_DEC = 0x40,        // -1------
    /** Secure messaging in response data fields (CT, CCT) */
    SEC_MSG_RSP_DATA = 0x20,   // --1-----
    /** Secure messaging in command data fields (CT, CCT) */
    SEC_MSG_CMD_DATA = 0x10,   // ---1----
    /** Confidentiality (CT) */
    CONF = 0x08,               // ----1---
    /** Cryptographic Checksum (CCT) */
    CHECKSUM = 0x04,           // -----1--
    /** Digital Signature (DST) */
    SIGN = 0x02,               // ------1-
    /** Cryptographic Authorization (CAT) */
    AUTHORIZE = 0x01,          // -------1

    // second byte. 0x00 if only first is present.
    /** Key Agreement (KAT) */
    KEY_AGR,                   // 1-------
}

export enum EKeyAccess {
    /** The key may be used by the Security Domain and any associated Application */
    SD_AND_AA = 0x00,
    /** The key may only be used by the Security Domain */
    SD_ONLY = 0x01,
    /** The key may be used by any Application associated with the Security Domain but not by the Security Domain itself */
    AA_ONLY = 0x02,
    // 0x03 - 0x1F: RFU
    // 0x20 - 0xFE: Proprietary
    /** Not available */
    NA = 0xFF,
}

