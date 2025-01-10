import Logger from '../../logger';
import { ICard } from "../../typesInternal";
import { BerObject } from '../../ber';
import { select as isoSelect } from '../../iso7816/commands';
import { getData as gpGetData } from './../commands';
import { hexEncode, type TBinData, importBinData } from '../../utils';
import { EPrivileges } from '../values'

type TSCP03KeyType = 'AES-128' | 'AES-192' | 'AES-256';

type TPrivilegeEncodingRules = {
    [key in keyof typeof EPrivileges]: {
        /** Byte index in privileges byte array. */
        0 : number,
        /** Bitmask to apply to byte */
        1: number,
        /** Expected result after applying bitmask */
        2: number,
    }
}
// ssd: ff fe c0    1111-1111 1111-1110 1100-0000
// app: 1e 86 00    0001-1110 1000-0110 0000-0000
const privEncRules: TPrivilegeEncodingRules = {
    // first byte
    SecurityDomain:            [0,0x80,0x80], // 1-------
    DAPVerification:           [0,0xc1,0xc0], // 11-----0
    DelegatedManagement:       [0,0xa0,0xa0], // 1-1-----
    CardLock:                  [0,0x10,0x10], // ---1----
    CardTerminate:             [0,0x08,0x08], // ----1---
    CardReset:                 [0,0x04,0x04], // -----1--
    CVMManagement:             [0,0x02,0x02], // ------1-
    MandatedDAPVerification:   [0,0xc1,0xc1], // 11-----1
 // second byte
    TrustedPath:               [1,0x80,0x80], // 1-------
    AuthorizedManagement:      [1,0x40,0x40], // -1------
    TokenManagement:           [1,0x20,0x20], // --1-----
    GlobalDelete:              [1,0x10,0x10], // ---1----
    GlobalLock:                [1,0x08,0x08], // ----1---
    GlobalRegistry:            [1,0x04,0x04], // -----1--
    FinalApplication:          [1,0x02,0x02], // ------1-
    GlobalService:             [1,0x01,0x01], // -------1
 // third byte
    ReceiptGeneration:         [2,0x80,0x80], // 1-------
    CipheredLoadFileDataBlock: [2,0x40,0x40], // -1------
    ContactlessActivation:     [2,0x20,0x40], // --1-----
    ContactlessSelfActivation: [2,0x10,0x40], // ---1----
}

type TPrivilegesList = {
    [key in keyof typeof EPrivileges]: boolean
}

export interface IGPCapabilities {
    /** `A0` tag(s). Info about supported SCP protocol types. At least one occurrence of tag `A0` shall be present. Every `A0` occurence will have its own entry in `supportedScpTypes` property */
    supportedScpTypes?: {
        [key: string]: {
            /** `A0/81` tag. List of supported options for protocol type (e.g. 0x15(dec 21) or  0x55(dec 85) for SCP02) */
            options: number[];
            /** `A0/82` tag. For SCP03. Supported keys */
            scp03Keys?: {
                [key in TSCP03KeyType]: boolean;
            };
            /** `A0/83` tag. For SCP81. Supported TLS cipher suites for SCP81. Defined in [RFC 4279], [RFC 4785], and [RFC 5487]. Limited to cipher suites actually referenced in [Amd B]. Each cipher suite number is itself a 2-byte data. */
            scp81Tls?: Uint8Array;
            /** `A0/84` tag. For SCP81. Maximum length of Pre Shared Key in bytes */
            scp81MaxPSKLen?: number;
        };
    };
    /** `81` tag. Present if the card supports Supplementary Security Domains. Bitmap of privileges that may be assigned to Supplementary Security Domains on card. */
    ssdPrivileges?: TPrivilegesList;
    /** `82` tag. Shall be present. Bitmap of privileges that may be assigned to Applications on card */
    appPrivileges?: TPrivilegesList;
}

function decodePrivileges(pByteArray: Uint8Array): TPrivilegesList {
    if (pByteArray.byteLength != 3) {
        throw new Error(`Unexpected privileges byte array length. Expected: 3 bytes, received: ${pByteArray} bytes.`)
    }
    let result: any = {};
    // console.log(privEncRules["0"]);
    for (const pName in privEncRules) {
        const pRules = privEncRules[pName];
        result[pName] = (pByteArray[pRules[0]] & pRules[1]) === pRules[2];
    }
    console.log(result);
    return result;
}

/** Gets available GlobalPlatform capabilities from a default applet and calls provided callback upon completion. */
export function getCapabilities(card: ICard, callback: (err: any, info: IGPCapabilities) => void): void
/** Gets available GlobalPlatform capabilities from a default applet and resolves upon completion. */
export function getCapabilities(card: ICard): Promise<IGPCapabilities>
/** Gets available GlobalPlatform capabilities from a default applet and calls provided callback or resolves upon completion. */
export function getCapabilities(
    card: ICard,
    callback?: ((error: any, info: IGPCapabilities) => void),
): void | Promise<IGPCapabilities> {

    if (typeof callback === 'undefined') {
        return getCapabilitiesFromAid(card, []);
    } else {
        getCapabilitiesFromAid(card, [], callback);
    }
}

/** Gets available GlobalPlatform capabilities from a given applet and calls provided callback upon completion. Empty aid means default applet will be used. */
export function getCapabilitiesFromAid(card: ICard, aid: TBinData, callback: (err: any, capabilities: IGPCapabilities) => void): void
/** Gets available GlobalPlatform capabilities from a given applet and resolves upon completion. Empty aid means default applet will be used. */
export function getCapabilitiesFromAid(card: ICard, aid: TBinData): Promise<IGPCapabilities>
/** Gets available GlobalPlatform capabilities from a given applet and calls provided callback or resolves upon completion. Empty aid means default applet will be used. */
export function getCapabilitiesFromAid(
    card: ICard,
    aid: TBinData,
    callback?: ((err: any, capabilities: IGPCapabilities) => void) | null,
): void | Promise<IGPCapabilities> {
    const importedAid = importBinData(aid);
    Logger.trace(`Getting GP capabilities from ${ !importedAid.byteLength ? 'default applet' : `applet "${hexEncode(importedAid)}"` } ...`);
    if (typeof callback === 'undefined' || !callback) {
        return new Promise((resolve, reject) => {
            const callback = (error: any, capabilities: IGPCapabilities) => {
                if (typeof error !== 'undefined') {
                    return reject(error);
                }
                return resolve(capabilities);
            };
            try {
                getCapabilitiesInternal(card, importedAid, callback);
            } catch (error: any) {
                return reject(error);
            }
        });
    } else {
        try {
            getCapabilitiesInternal(card, importedAid, callback);
        } catch (error: any) {
            callback(error, {});
        }
    }
}

function getCapabilitiesInternal(card: ICard, aid: Uint8Array, callback: (err: any, capabilities: IGPCapabilities) => void): void {
    const cardCapsResult: IGPCapabilities = {};
    Logger.trace('Selecting applet...');
    card.issueCommand(isoSelect(aid))
        .then((defaultSelectResponse) => {
            // parsing response to default select and getting ISD AID
            if (!defaultSelectResponse.isOk || defaultSelectResponse.dataLength < 1) {
                return Promise.reject(new Error(`Error response to select: ${defaultSelectResponse.toString()}(${defaultSelectResponse.meaning})`));
            }

            return Promise.resolve();
        })
        .then(() => {
            Logger.trace('Reading card capabilities...');
            return new Promise<void>((resolve) => {
                card.issueCommand(gpGetData(0x00, 0x67))
                    .then((getDataResponse) => {
                        if (!getDataResponse.isOk || getDataResponse.dataLength < 1) {
                            const errMsg = `Error response to GET_DATA (tag 0x67): ${getDataResponse.toString()}(${getDataResponse.meaning})`;
                            Logger.debug(errMsg);
                            return resolve();
                        }

                        let responseBer: BerObject;
                        try {
                            responseBer = BerObject.parse(getDataResponse.data);
                        } catch (error: any) {
                            const errMsg = `Error parsing GET_DATA response (tag 0x67): ${error.message}; Data:[${hexEncode(getDataResponse.data)}]`;
                            Logger.debug(errMsg);
                            return resolve();
                        }

                        responseBer.print((line) => {
                            Logger.debug(line);
                        });

                        /** Card recognition data */
                        const cardCapData = responseBer.search('/67');

                        if (cardCapData.length !== 1) {
                            const errMsg = 'Unexpected data';
                            Logger.warn(errMsg);
                            return resolve();
                        }

                        (cardCapData[0].value as BerObject[]).forEach((cardCapDataElem) => {
                            try {
                                switch (cardCapDataElem.tag.hex.toLowerCase()) {
                                    case 'a0': //SCP info
                                        let scpType: string | undefined;
                                        let scpOptions: number[] = [];
                                        let scp03Keys: {[key in TSCP03KeyType]: boolean} | undefined;
                                        let scp81Tls: Uint8Array = new Uint8Array(0);
                                        let scp81MaxPSKLen: number | undefined;
                                        (cardCapDataElem.value as BerObject[]).forEach((scpInfoElem) => {
                                            switch (scpInfoElem.tag.hex) {
                                                case '80': // SCP type, 1 byte
                                                    if ((scpInfoElem.value as Uint8Array).byteLength === 1) {
                                                        scpType = hexEncode((scpInfoElem.value as Uint8Array))
                                                    }
                                                    break;
                                                case '81': // supported options, var len
                                                    scpOptions = [...(scpInfoElem.value as Uint8Array)];
                                                    break;
                                                case '82': // SP03 keys var len
                                                    if ((scpInfoElem.value as Uint8Array).byteLength === 1) {
                                                        const valByte = (scpInfoElem.value as Uint8Array)[0];
                                                        scp03Keys = {
                                                            "AES-128": (valByte & 0x01) > 0,
                                                            "AES-192": (valByte & 0x02) > 0,
                                                            "AES-256": (valByte & 0x04) > 0,
                                                        }
                                                    }
                                                    break;
                                                case '83': // SCP81 supported TLS cipher suites, var len
                                                    scp81Tls = scpInfoElem.value as Uint8Array;
                                                    break;
                                                case '84': // SCP81 max pre shared key length in bytes, 1 byte
                                                    if ((scpInfoElem.value as Uint8Array).byteLength === 1) {
                                                        scp81MaxPSKLen = (scpInfoElem.value as Uint8Array)[0];
                                                    }
                                                    break;
                                                default:
                                                    break;
                                            }
                                        })
                                        if (typeof scpType === 'string' && scpType.length > 0 && scpOptions.length > 0) {
                                            if (typeof cardCapsResult.supportedScpTypes === 'undefined')
                                                cardCapsResult.supportedScpTypes = {};

                                            cardCapsResult.supportedScpTypes[scpType] = { options: scpOptions };

                                            if (typeof scp03Keys !== 'undefined')
                                                cardCapsResult.supportedScpTypes[scpType].scp03Keys = scp03Keys;

                                            if (scp81Tls.byteLength > 0)
                                                cardCapsResult.supportedScpTypes[scpType].scp81Tls = scp81Tls;

                                            if (typeof scp81MaxPSKLen === 'number')
                                                cardCapsResult.supportedScpTypes[scpType].scp81MaxPSKLen = scp81MaxPSKLen;
                                        }
                                        break;
                                    case '81':
                                        cardCapsResult.ssdPrivileges = decodePrivileges(cardCapDataElem.value as Uint8Array);
                                        break;
                                    case '82':
                                        cardCapsResult.appPrivileges = decodePrivileges(cardCapDataElem.value as Uint8Array);
                                        break;
                                    case '83':
                                        break;
                                    case '84':
                                        break;
                                    case '85':
                                        break;
                                    case '86':
                                        break;
                                    case '87':
                                        break;
                                    case '88':
                                        break;
                                    default:
                                        break;
                                }
                            } catch (error: any) {
                                const errMsg = `Error reading tag "${cardCapDataElem.tag.hex}": ${error.message}`;
                                Logger.debug(errMsg);
                                return;
                            }
                        })

                        return resolve();
                    })
                    .catch((error) => {
                        const errMsg = `Error getting card data (tag 0x67): ${error.message}`;
                        Logger.debug(errMsg);
                        return resolve();
                    })
            })
        })
        .then(() => {
            callback(undefined, cardCapsResult);
            return Promise.resolve();
        })
        .catch((error: any) => {
            callback(error, cardCapsResult)
            return;
        })
}