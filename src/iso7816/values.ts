/** List of Ins bytes as defined in Iso7816-4(2014) specifications */
export enum EIns {
    /** 0x04; see Iso7816-9 */
    DEACTIVATE_FILE = 0x04,
    /** 0x06; see 11.3.10 of Iso7816-4(2014) */
    DEACTIVATE_RECORD = 0x06,
    /** 0x08; see 11.3.9 of Iso7816-4(2014) */
    ACTIVATE_RECORD = 0x08,
    /** 0x0C; see 11.3.8 of Iso7816-4(2014) */
    ERASE_RECORD = 0x0c,
    /** 0x0E; see 11.2.7 of Iso7816-4(2014) */
    ERASE_BINARY_EVEN = 0x0e,
    /** 0x0F; see 11.2.7 of Iso7816-4(2014) */
    ERASE_BINARY_ODD = 0x0f,
    /** 0x10; see Iso7816-7 */
    PERFORM_SCQL_OP = 0x10,
    /** 0x12; see Iso7816-7 */
    PERFORM_TRANSACTION_OP = 0x12,
    /** 0x14; see Iso7816-7 */
    PERFORM_USER_OP = 0x14,
    /** 0x20; see 11.5.6 of Iso7816-4(2014) */
    VERIFY_REF_DATA = 0x20,
    /** 0x21; see 11.5.6 of Iso7816-4(2014) */
    VERIFY_REF_DO = 0x21,
    /** 0x22; see 11.5.11 of Iso7816-4(2014) */
    MANAGE_SECURITY_ENV = 0x22,
    /** 0x24; see 11.5.7 of Iso7816-4(2014) */
    CHANGE_REF_DATA = 0x24,
    /** 0x25; see 11.5.7 of Iso7816-4(2014) */
    CHANGE_REF_DO = 0x25,
    /** 0x26; see 11.5.9 of Iso7816-4(2014) */
    DISABLE_VERIFY_REQMT = 0x26,
    /** 0x28; see 11.5.8 of Iso7816-4(2014) */
    ENABLE_VERIFY_REQMT = 0x28,
    /** 0x2A; see Iso7816-8 */
    PERFORM_SECURITY_OP_EVEN = 0x2a,
    /** 0x2B; see Iso7816-8 */
    PERFORM_SECURITY_OP_ODD = 0x2b,
    /** 0x2C; see 11.5.10 of Iso7816-4(2014) */
    RESET_RETRY_COUNT_EVEN = 0x2c,
    /** 0x2D; see 11.5.10 of Iso7816-4(2014) */
    RESET_RETRY_COUNT_ODD = 0x2d,
    /** 0x2E; see Iso7816-8 */
    PERFORM_BIOMETRIC_OP_EVEN = 0x2e,
    /** 0x2F; see Iso7816-8 */
    PERFORM_BIOMETRIC_OP_ODD = 0x2f,
    /** 0x33; see 11.6.1 of Iso7816-4(2014) */
    COMPARE = 0x33,
    /** 0x34; see 11.6.2 of Iso7816-4(2014) */
    GET_ATTRIBUTE_EVEN = 0x34,
    /** 0x35; see 11.6.2 of Iso7816-4(2014) */
    GET_ATTRIBUTE_ODD = 0x35,
    /** 0x40; see Iso7816-13 */
    APP_MGMT_REQST_EVEN = 0x40,
    /** 0x41; see Iso7816-13 */
    APP_MGMT_REQST_ODD = 0x41,
    /** 0x44; see Iso7816-9 */
    ACTIVATE_FILE = 0x44,
    /** 0x46; see Iso7816-8 */
    GEN_ASYMM_KEY_PAIR_EVEN = 0x46,
    /** 0x47; see Iso7816-8 */
    GEN_ASYMM_KEY_PAIR_ODD = 0x47,
    /** 0x70; see 11.1.2 of Iso7816-4(2014) */
    MANAGE_CHANNEL = 0x70,
    /** 0x82; see 11.5.4 of Iso7816-4(2014) */
    EXT_MUT_AUTH = 0x82,
    /** 0x84; see 11.5.3 of Iso7816-4(2014) */
    GET_CHALLENGE = 0x84,
    /** 0x86; see 11.5.5 of Iso7816-4(2014) */
    GENERAL_AUTH_EVEN = 0x86,
    /** 0x87; see 11.5.5 of Iso7816-4(2014) */
    GENERAL_AUTH_ODD = 0x87,
    /** 0x88; 0x88; see 11.5.2 of Iso7816-4(2014) */
    INT_AUTH = 0x88,
    /** 0xA0; see 11.2.6 of Iso7816-4(2014) */
    SEARCH_BIN_EVEN = 0xa0,
    /** 0xA1; see 11.2.6 of Iso7816-4(2014) */
    SEARCH_BIN_ODD = 0xa1,
    /** 0xA2; see 11.3.7 of Iso7816-4(2014) */
    SEARCH_RECORD = 0xa2,
    /** 0xA4; see 11.1.1 of Iso7816-4(2014) */
    SELECT = 0xa4,
    /** 0xA5; see 11.4.2 of Iso7816-4(2014) */
    SELECT_DATA = 0xa5,
    /** 0xB0; see 11.2.3 of Iso7816-4(2014) */
    READ_BINARY_EVEN = 0xb0,
    /** 0xB1; see 11.2.3 of Iso7816-4(2014) */
    READ_BINARY_ODD = 0xb1,
    /** 0xB2; see 11.3.3 of Iso7816-4(2014) */
    READ_RECORD_EVEN = 0xb2,
    /** 0xB3; see 11.3.3 of Iso7816-4(2014) */
    READ_RECORD_ODD = 0xb3,
    /** 0xC0; see 11.7.1 of Iso7816-4(2014) */
    GET_RESPONSE = 0xc0,
    /** 0xC2; see 11.7.2 of Iso7816-4(2014) */
    ENVELOPE_EVEN = 0xc2,
    /** 0xC3; see 11.7.2 of Iso7816-4(2014) */
    ENVELOPE_ODD = 0xc3,
    /** 0xCA; see 11.4.3 of Iso7816-4(2014) */
    GET_DATA_EVEN = 0xca,
    /** 0xCB; see 11.4.4 of Iso7816-4(2014) */
    GET_DATA_ODD = 0xcb,
    /** 0xCC; see 11.4.3 of Iso7816-4(2014) */
    GET_NEXT_DATA_EVEN = 0xcc,
    /** 0xCD; see 11.4.4 of Iso7816-4(2014) */
    GET_NEXT_DATA_ODD = 0xcd,
    /** 0xCF; see Iso7816-9 */
    NAMAGE_DATA = 0xcf,
    /** 0xD0; see 11.2.4 of Iso7816-4(2014) */
    WRITE_BINARY_EVEN = 0xd0,
    /** 0xD1; see 11.2.4 of Iso7816-4(2014) */
    WRITE_BINARY_ODD = 0xd1,
    /** 0xD2; see 11.3.4 of Iso7816-4(2014) */
    WRITE_RECORD = 0xd2,
    /** 0xD6; see 11.2.5 of Iso7816-4(2014) */
    UPDATE_BINARY_EVEN = 0xd6,
    /** 0xD7; see 11.2.5 of Iso7816-4(2014) */
    UPDATE_BINARY_ODD = 0xd7,
    /** 0xD8; see 11.4.7 of Iso7816-4(2014) */
    PUT_NEXT_DATA_EVEN = 0xd8,
    /** 0xD9; see 11.4.7 of Iso7816-4(2014) */
    PUT_NEXT_DATA_ODD = 0xd9,
    /** 0xDA; see 11.4.6 of Iso7816-4(2014) */
    PUT_DATA_EVEN = 0xda,
    /** 0xDB; see 11.4.6 of Iso7816-4(2014) */
    PUT_DATA_ODD = 0xdb,
    /** 0xDC; see 11.3.5 of Iso7816-4(2014) */
    UPDATE_RECORD_EVEN = 0xdc,
    /** 0xDD; see 11.3.5 of Iso7816-4(2014) */
    UPDATE_RECORD_ODD = 0xdd,
    /** 0xDE; see 11.4.8 of Iso7816-4(2014) */
    UPDATE_DATA_EVEN = 0xde,
    /** 0xDF; see 11.4.8 of Iso7816-4(2014) */
    UPDATE_DATA_ODD = 0xdf,
    /** 0xE0; see Iso7816-9 */
    CREATE_FILE = 0xe0,
    /** 0xE2; see 11.3.6 of Iso7816-4(2014) */
    APPEND_RECORD = 0xe2,
    /** 0xE4; see Iso7816-9 */
    DELETE_FILE = 0xe4,
    /** 0xE6; see Iso7816-9 */
    TERMINATE_DF = 0xe6,
    /** 0xE8; see Iso7816-9 */
    TERMINATE_EF = 0xe8,
    /** 0xEA; see Iso7816-13 */
    LOAD_APP_EVEN = 0xea,
    /** 0xEB; see Iso7816-13 */
    LOAD_APP_ODD = 0xeb,
    /** 0xEE; see Iso7816-9 */
    DELETE_DATA = 0xee,
    /** 0xEC; see Iso7816-13 */
    REMOVE_APP_EVEN = 0xec,
    /** 0xED; see Iso7816-13 */
    REMOVE_APP_ODD = 0xed,
    /** 0xFE; see Iso7816-9 */
    TERMINATE_CARD_USAGE = 0xfe,
}
