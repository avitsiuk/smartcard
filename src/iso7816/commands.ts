import { TBinData } from '../utils';
import CommandApdu from '../commandApdu';
import { EIns as isoIns } from './values';

export interface ISelectOptions {
    /** P1 (Selection method); Default: `name`
     * - `id_0` - Select MF, DF or EF
     * - `id_1` - Select child DF
     * - `id_2` - Select EF under the current DF
     * - `id_3` - Select parent DF of the current DF
     * - `name` - Select by DF name
     * - `path_0` - Select by path  from the MF
     * - `path_1` - Select by path from the current DF
     * - `do_0` - Select DO in the current template
     * - `do_1` - Select parent DO of the constructed DO setting the current template
     */
    selectBy?:
        | 'id_0'
        | 'id_1'
        | 'id_2'
        | 'id_3'
        | 'name'
        | 'path_0'
        | 'path_1'
        | 'do_0'
        | 'do_1';
    /** P2 (File or DO occurrence); Default: `first`
     * - `first` - First or only occurrence
     * - `last` - Last occurrence
     * - `next` - Next occurrence
     * - `prev` - Previous occurrence
     */
    occurence?: 'first' | 'last' | 'next' | 'prev';
    /** P2 (Response requirements); Default: `fci`
     * - `fci` - Return FCI template, optional use of FCI tag and length
     * - `cp` - Return CP template, mandatory use of CP tag and length
     * - `fmd` - Return FMD template, mandatory use of FMD tag and length; Return the tags belonging to the template set by the selection of a constructed DO as a tag list
     * - `le` - No response data if Le field absent, or proprietary if Le field present  */
    response?: 'fci' | 'cp' | 'fmd' | 'le';
}

/** When completed, the command opens the logical channel (see 5.4.2) numbered in CLA (see 5.4.1), if not yet opened, and sets a current structure within that logical channel. Subsequent commands may implicitly refer to the current structure through that logical channel.
 * @param data - Absent or file identifier or path or DF name or tag
 * @param opts - additional command options encoded in P1 and P2
 */
export function select(
    data?: TBinData,
    opts: ISelectOptions = {},
): CommandApdu {
    const cmd = new CommandApdu().setIns(isoIns.SELECT);

    if (typeof data !== 'undefined') {
        try {
            cmd.setData(data);
        } catch (error: any) {
            throw new Error(`select command error: ${error}`);
        }
    }

    // P1
    let p1 = 0x04; // default, select by name
    if (typeof opts.selectBy !== 'undefined') {
        p1 = 0x00;
        switch (opts.selectBy) {
            case 'id_0':
                break;
            case 'id_1':
                p1 |= 0x01;
                break;
            case 'id_2':
                p1 |= 0x02;
                break;
            case 'id_3':
                p1 |= 0x03;
                break;
            case 'name':
                p1 |= 0x04;
                break;
            case 'path_0':
                p1 |= 0x08;
                break;
            case 'path_1':
                p1 |= 0x09;
                break;
            case 'do_0':
                p1 |= 0x10;
                break;
            case 'do_1':
                p1 |= 0x13;
                break;
            default:
                break;
        }
    }
    cmd.setP1(p1);

    // P2
    let p2 = 0x00; // default, first or only, return fci template
    if (typeof opts.occurence !== 'undefined') {
        p2 &= 0x0c;
        switch (opts.occurence) {
            case 'first':
                break;
            case 'last':
                p2 |= 0x01;
                break;
            case 'next':
                p2 |= 0x02;
                break;
            case 'prev':
                p2 |= 0x03;
                break;
            default:
                break;
        }
    }
    if (typeof opts.response !== 'undefined') {
        p2 &= 0x03;
        switch (opts.response) {
            case 'fci':
                break;
            case 'cp':
                p2 |= 0x04;
                break;
            case 'fmd':
                p2 |= 0x08;
                break;
            case 'le':
                p2 |= 0x0c;
                break;
            default:
                break;
        }
    }
    cmd.setP2(p2);
    return cmd;
}

/**
 * @param le - number of bytes to get
 */
export function getResponse(le: number): CommandApdu {
    if (le < 0 || le > 255) {
        throw new Error('Wrong le value');
    }
    const cmd = new CommandApdu().setIns(isoIns.GET_RESPONSE).setLe(le);
    return cmd;
}

/**
 * Verify refecerce data (pins, passwords etc...)
 * @param refNum - reference data number(value between 0 and 31)
 * @param dataToVerify - actual data for card to verify (password, pin etc...)
 * @param reset - (Default: `false`); if true, data must be empty; if `true`, the command shall set the verification status of the relevant reference data as "not verified"
 * @param refIsSpecific - (Default: `true`). If true, `refNum` indicates specific reference data (e.g. DF specific password or key); otherwise it indicates global reference data (e.g. MF specific password or key) */
export function verifyRefData(
    refNum: number,
    dataToVerify: TBinData | null,
    reset: boolean = false,
    refIsSpecific: boolean = true,
): CommandApdu {
    if (refNum < 0 || refNum > 31) {
        throw new Error(
            `Data reference number must be between 0 and 31; received: ${refNum}`,
        );
    }

    if (reset && dataToVerify) {
        throw new Error(`With reset set to "true", data must be null`);
    }

    const cmd = new CommandApdu().setIns(isoIns.VERIFY_REF_DATA);

    if (reset) cmd.setP1(0xff);

    let p2 = refNum;
    if (refIsSpecific) p2 |= 0x80;

    cmd.setP2(p2);

    if (dataToVerify) {
        try {
            cmd.setData(dataToVerify);
        } catch (error: any) {
            throw new Error(`verifyRefData command error: ${error}`);
        }
    }

    return cmd;
}

/**
 * Set refecerce data (pins, passwords etc...)
 * @param refNum - reference data number(value between 0 and 31)
 * @param data - new data
 * @param refIsSpecific - (Default: `true`). If true, `refNum` indicates specific reference data (e.g. DF specific password or key); otherwise it indicates global reference data (e.g. MF specific password or key) */
export function changeRefData(
    refNum: number,
    data: TBinData,
    refIsSpecific: boolean = true,
): CommandApdu {
    if (refNum < 0 || refNum > 31) {
        throw new Error(
            `Data reference number must be between 0 and 31; received: ${refNum}`,
        );
    }

    // 00 - [verification data][new data]; 01 - [new data]
    const cmd = new CommandApdu().setIns(isoIns.CHANGE_REF_DATA).setP1(0x01);

    let p2 = refNum;

    if (refIsSpecific) {
        p2 |= 0x80;
    }

    cmd.setP2(p2);

    try {
        cmd.setData(data);
    } catch (error: any) {
        throw new Error(`changeRefData command error: ${error}`);
    }

    return cmd;
}

/**
 * Internal authenticate. The command prompts the card to generate authentication data using the challenge data sent by the interface device and a corresponding secret, like a key, stored in the card.
 * @param data - Authentication-related data (e.g. challenge).
 * @param algorithm - Default: `0`. A byte indicating the algorithm to use: either a cryptographic algorithm or a biometric algorithm (see ISO/IEC 7816-11). '00' means that no information is given.
 * @param refDataQualifier - Default: 0. Qualifier, i.e. number of the reference data or number of the secret, Must be between 0 and 31.
 * @param isSpecificQualifier - Default: `false`. If `false`, `dataQualifier` indicates global reference data (e.g. MF specific password or key). If `true`, `dataQualifier` indicates specific reference data (e.g. DF specific password or key).
 */
export function intAuth(
    data: TBinData = new Uint8Array(0),
    algorithm: number = 0,
    refDataQualifier: number = 0,
    isSpecificQualifier: boolean = false,
) {
    if (refDataQualifier < 0 || refDataQualifier > 31) {
        throw new Error(
            'intAuth command error: refDataQualifier must be in the range 0..31',
        );
    }
    let p2 = refDataQualifier & 0x1f;
    if (isSpecificQualifier) {
        p2 |= 0x80;
    }

    let cmd = new CommandApdu()
        .setIns(isoIns.INT_AUTH)
        .setP1(algorithm)
        .setP2(p2);

    try {
        cmd.setData(data);
    } catch (error: any) {
        throw new Error(`intAuth command error: ${error}`);
    }

    return cmd;
}

/**
 * The command requires the issuing of a challenge (e.g. a random number for a cryptographic authentication or a sentence to prompt for a biometric authentication using voiceprints) for use in a security-related procedure (e.g. EXTERNAL AUTHENTICATE command).
 * @param algorithm - Default: `0`. A byte indicating the algorithm to use: either a cryptographic algorithm or a biometric algorithm (see ISO/IEC 7816-11). '00' means that no information is given.
 */
export function getChallenge(algorithm: number): CommandApdu {
    let cmd = new CommandApdu()
        .setIns(isoIns.GET_CHALLENGE)
        .setP1(algorithm)
        .setP2(0);

    return cmd;
}

/**
 * External (mutual) authenticate. The command conditionally updates the security status using the result (yes or no) or the computation by the card based on a challenge previously issued by the card (e.g. by a `GET_CHALLENGE` command), a key possibly secret stored in the card and authentication data transmitted by the interface device. In case of `EXTERNAL_AUTHENTICATE` command the response data field is empty.
 * `MUTUAL_AUTHENTICATE` uses the same functionality as `EXTERNAL` and `INTERNAL_AUTHENTICATE` commands. It is based upon a previous `GET_CHALLENGE` command and a secret key stored in the card. In case of `MUTUAL_AUTHENTICATE` command the response data field contains card's authentication-related data.
 * @param data - Authentication-related data (e.g. challenge).
 * @param algorithm - Default: `0`. A byte indicating the algorithm to use: either a cryptographic algorithm or a biometric algorithm (see ISO/IEC 7816-11). '00' means that no information is given.
 * @param refDataQualifier - Default: 0. Qualifier, i.e. number of the reference data or number of the secret, Must be between 0 and 31.
 * @param isSpecificQualifier - Default: `false`. If `false`, `dataQualifier` indicates global reference data (e.g. MF specific password or key). If `true`, `dataQualifier` indicates specific reference data (e.g. DF specific password or key).
 */
export function extMutAuth(
    data: TBinData = new Uint8Array(0),
    algorithm: number = 0,
    refDataQualifier: number = 0,
    isSpecificQualifier: boolean = false,
) {
    if (refDataQualifier < 0 || refDataQualifier > 31) {
        throw new Error(
            'intAuth command error: refDataQualifier must be in the range 0..31',
        );
    }

    let p2 = refDataQualifier & 0x1f;

    if (isSpecificQualifier) {
        p2 |= 0x80;
    }

    let cmd = new CommandApdu()
        .setIns(isoIns.EXT_MUT_AUTH)
        .setP1(algorithm)
        .setP2(p2);

    try {
        cmd.setData(data);
    } catch (error: any) {
        throw new Error(`extMutAuth command error: ${error}`);
    }

    return cmd;
}

/** Retrievs the value field of a DO belonging to the current template. It may be the content of an EF supporting DOs
 * @param p1 - See 11.4.1.1 of Iso7816-4(2014)
 * @param p2 - See 11.4.1.1 of Iso7816-4(2014)
 */
export function getDataEven(p1: number, p2: number): CommandApdu {
    let cmd = new CommandApdu()
        .setIns(isoIns.GET_DATA_EVEN)
        .setP1(p1)
        .setP2(p2);

    return cmd;
}

/** Retrievs the value field of one or several DOs according to the arguments of the command.
 * @param p1 - See 11.4.1.2 of Iso7816-4(2014)
 * @param p2 - See 11.4.1.2 of Iso7816-4(2014)
 * @param data - Identical to `SELECT_DATA` data field. See 11.4.2.1 (Tables 86 and 87) of Iso7816-4(2014)
 */
export function getDataOdd(
    p1: number,
    p2: number,
    data: TBinData,
): CommandApdu {
    let cmd = new CommandApdu().setIns(isoIns.GET_DATA_ODD).setP1(p1).setP2(p2);

    try {
        cmd.setData(data);
    } catch (error: any) {
        throw new Error(`getDataOdd command error: ${error}`);
    }

    return cmd;
}
