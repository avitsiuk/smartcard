const default128Key = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];

/** Default 16 byte (128 bits) test static keys used in SCP02/SCP03 */
export const defaultStatic128Keys = {
    enc: default128Key,
    mac: default128Key,
    dek: default128Key,
};

/** List of Ins bytes as defined in GlobalPlatformCard specifications (2.2.1/2.3.1)*/
export enum ins {
    // only for SCP
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
