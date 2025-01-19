import CommandApdu from '../commandApdu';
import { TBinData, importBinData } from '../utils';
import { EIns as gpIns } from './values';
import { EIns as isoIns } from '../iso7816/values';
import { Tag, IBerObjInfo, BerObject } from '../ber/index';

/** Used to retrieve either a single BER-TLV-coded data object, which may be constructed, or a set of BER-TLV-coded data objects.
 * @param highTagByte - high order tag byte (or `0x00`, if tag is 1 byte long)
 * @param lowTagByte - low order tag byte
 * @param data - This shall be empty unless a tag list and/or a MAC is required. For retrieving a list of applications present on the card (P1-P2 set to '0x2F00') a tag list shall be present and coded as '0x5C00'.
*/
export function getData(highTagByte: number, lowTagByte: number, data?: TBinData): CommandApdu {

    const cmd = new CommandApdu()
        .setCla(0x80)
        .setIns(gpIns.GET_DATA)
        .setP1(highTagByte)
        .setP2(lowTagByte);

    if(typeof data !== 'undefined') {
        try {
            cmd.setData(data);
        } catch (error: any) {
            throw new Error(`getData command error: ${error}`);
        }
    }

    return cmd;
}

/** The INITIALIZE UPDATE command is used, during explicit initiation of a Secure Channel, to transmit card and session data between the card and the host. This command initiates the initiation of a Secure Channel Session.
 * @param keyVer - defines the Key Version Number within the Security Domain to be used to initiate the Secure Channel Session. If this value is zero, the first available key chosen by the Security Domain will be used.
 * @param hostChallenge - bytes of host challenge. This challenge, chosen by the off-card entity, should be unique to each session.
*/
export function initUpdate(
    keyVer: number,
    hostChallenge: TBinData,
) {
    let cmd = new CommandApdu()
        .setProprietary()
        .setIns(gpIns.INIT_UPDATE)
        .setP1(keyVer)
        .setP2(0)
        .setLe(0);

    try {
        cmd.setData(hostChallenge);
    } catch (error: any) {
        throw new Error(`initUpdate command error: ${error}`)
    }
    return cmd;
}

/**
 * The EXTERNAL AUTHENTICATE command is used by the card, during explicit initiation of a Secure Channel, to authenticate the host and to determine the level of security required for all subsequent commands.
 * @param secLvl - (Default:`0`) Defines the level of security for all secure messaging commands following this EXTERNAL AUTHENTICATE command (it does not apply to this command) and within this Secure Channel. Valid `secLvl` values:
 * - `0x00` - No secure messaging expected
 * - `0x01` - C-MAC
 * - `0x03` - C-DECRYPTION, C-MAC
 * - `0x10` - R-MAC
 * - `0x11` - R-MAC, C-MAC
 * - `0x13` - R-MAC, C-DECRYPTION, C-MAC
 */
export function extAuth(hostCryptogram: TBinData, secLvl: 0 | 1 | 3 | 16 | 17 | 19 = 0) {
    let cmd = new CommandApdu()
        .setProprietary()
        .setSecMgsType(1)
        .setIns(isoIns.EXT_MUT_AUTH)
        .setP1(secLvl)
        .setP2(0x00);

    try {
        cmd.setData(hostCryptogram);
    } catch (error: any) {
        throw new Error(`extAuth command error: ${error}`)
    }

    return cmd;
}

/**
 * Internal authenticate
 * @param key - ephemeral OCE key agreement public key
 * @param secLvl - (Default:`0x34`) Defines the level of security for all secure messaging commands following this INTERNAL_AUTHENTICATE command (it does not apply to this command) and within this Secure Channel
 * Possible `secLvl` values:
 * `0x34` - C-MAC and R-MAC only
 * `0x3C` - C-MAC, C-DECRYPTION, R-MAC, R-ENCRYPTION
 * @param includeId - (Default: `false`) If true, a passed id can be included
 * @param id - id to include if `includeId` parameter has been set to `true`
 */
export function intAuth(
    key: TBinData,
    secLvl: 0x34 | 0x3c = 0x34,
    includeId: boolean = false,
    id: TBinData = new Uint8Array(0),
) {
    let _key: Uint8Array;
    try {
        _key = importBinData(key);
    } catch (error: any) {
        throw new Error(`Key error: ${error.message}`);
    }

    let berObjInfo: IBerObjInfo = {
        tag: Tag.root,
        value: [
            {
                tag: 'A6',
                value: [
                    { tag: '90', value: [0x11, includeId ? 0x04 : 0x00] },
                    { tag: '95', value: [secLvl] },
                    { tag: '80', value: [0x88] },
                    { tag: '81', value: [Math.floor(_key.byteLength / 2)] },
                ],
            },
            { tag: '5F49', value: _key },
        ],
    };

    if (includeId) {
        ((berObjInfo.value as IBerObjInfo[])[0].value as IBerObjInfo[]).push({
            tag: '84',
            value: id,
        });
    }

    let cmd = new CommandApdu()
        .setProprietary()
        .setType(4)
        .setSecMgsType(0)
        .setIns(isoIns.INT_AUTH)
        .setP1(0x00) // key version
        .setP2(0x00) // key identifier
        .setData(BerObject.create(berObjInfo).serialize());
    return cmd;
}

/**
 * Mutual authenticate
 * @param key - ephemeral OCE key agreement public key
 * @param secLvl - (Default:`0x34`) Defines the level of security for all secure messaging commands following this INTERNAL_AUTHENTICATE command (it does not apply to this command) and within this Secure Channel
 * Possible `secLvl` values:
 * `0x34` - C-MAC and R-MAC only
 * `0x3C` - C-MAC, C-DECRYPTION, R-MAC, R-ENCRYPTION
 * @param includeId - (Default: `false`) If true, a passed id can be included
 * @param id - id to include if `includeId` parameter has been set to `true`
 */
export function mutAuth(
    key: TBinData,
    secLvl: 0x34 | 0x3c = 0x34,
    includeId: boolean = false,
    id: TBinData = new Uint8Array(0),
) {
    let _key: Uint8Array;
    try {
        _key = importBinData(key);
    } catch (error: any) {
        throw new Error(`Key error: ${error.message}`);
    }

    let berObjInfo: IBerObjInfo = {
        tag: Tag.root,
        value: [
            {
                tag: 'A6',
                value: [
                    { tag: '90', value: [0x11, includeId ? 0x04 : 0x00] },
                    { tag: '95', value: [secLvl] },
                    { tag: '80', value: [0x88] },
                    { tag: '81', value: [Math.floor(_key.byteLength / 2)] },
                ],
            },
            { tag: '5F49', value: _key },
        ],
    };

    if (includeId) {
        ((berObjInfo.value as IBerObjInfo[])[0].value as IBerObjInfo[]).push({
            tag: '84',
            value: id,
        });
    }

    let cmd = new CommandApdu()
        .setProprietary()
        .setType(4)
        .setSecMgsType(0)
        .setIns(isoIns.EXT_MUT_AUTH)
        .setP1(0x00) // key version
        .setP2(0x00) // key identifier
        .setData(BerObject.create(berObjInfo).serialize());
    return cmd;
}
