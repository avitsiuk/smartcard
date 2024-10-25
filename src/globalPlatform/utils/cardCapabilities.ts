import Logger from '../../logger';
import { ICard } from "../../typesInternal";
import { BerObject } from '../../ber';
import { select as isoSelect } from '../../iso7816/commands';
import { getData as gpGetData } from './../commands';
import { hexEncode } from '../../utils';

type TSCPType = '02' | '03' | '80' | '81';
type TSCP03KeyType = 'AES-128' | 'AES-192' | 'AES-256';

export interface IGPCardCapabilities {
    /** Info about supported SCP protocol types (tag `A0`). Every `A0` tag will have own entry in `supportedScpTypes`*/
    supportedScpTypes?: {
        [key: string]: {
            /** List of supported options for that protocol (e.g. 0x15(dec 21) or  0x55(dec 85) for SCP02) (tag `A0/81`) */
            options: number[];
            /** Supported keys for SCP03  (tag `A0/82`) */
            scp03Keys?: {
                [key in TSCP03KeyType]: boolean;
            };
            /** Supported TLS cipher suites for SCP81 (hex string) (tag `A0/83`). Defined in [RFC 4279], [RFC 4785], and [RFC 5487]. Limited to cipher suites actually referenced in [Amd B]. Each cipher suite number is itself a 2-byte data.*/
            scp81Tls?: Uint8Array;
            /** Maximum length of Pre Shared Key in bytes (for SCP81 only) (tag `A0/84`) */
            scp81MaxPSKLen?: number;
        };
    };
}

/** Gets available card data and calls provided callback upon completion */
export function gpCardCapabilities(card: ICard, callback: (err: any, capabilities: IGPCardCapabilities) => void): void
/** Gets available card data and resolves upon completion */
export function gpCardCapabilities(card: ICard): Promise<IGPCardCapabilities>
/** Gets available card data and calls provided callback or resolves upon completion */
export function gpCardCapabilities(
    card: ICard,
    callback?: (err: any, capabilities: IGPCardCapabilities) => void,
): void | Promise<IGPCardCapabilities> {
    if (typeof callback === 'undefined') {
        return new Promise((resolve, reject) => {
            const callback = (error: any, capabilities: IGPCardCapabilities) => {
                if (typeof error !== 'undefined') {
                    return reject(error);
                }
                return resolve(capabilities);
            };
            try {
                gpCardCapabilitiesInternal(card, callback);
            } catch (error: any) {
                return reject(error);
            }
        });
    } else {
        try {
            gpCardCapabilitiesInternal(card, callback);
        } catch (error: any) {
            callback(error, {});
        }
    }
}

function gpCardCapabilitiesInternal(card: ICard, callback: (err: any, capabilities: IGPCardCapabilities) => void): void {
    Logger.trace('Getting GP card capabilities...');
    const cardCapsResult: IGPCardCapabilities = {};
    Logger.trace('Selecting default applet...');
    card.issueCommand(isoSelect())
        .then((defaultSelectResponse) => {
            // parsing response to default select and getting ISD AID
            if (!defaultSelectResponse.isOk || defaultSelectResponse.dataLength < 1) {
                return Promise.reject(new Error(`Error response to default select: ${defaultSelectResponse.toString()}(${defaultSelectResponse.meaning})`));
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
                                        break;
                                    case '82':
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