import Logger from '../../logger';
import { ICard } from "../../typesInternal";
import { BerObject, Asn1Utils } from '../../ber';
import { select as isoSelect } from '../../iso7816/commands';
import { getData as gpGetData } from './../commands';
import { GP_OID_STR } from './../values';
import { hexDecode, hexEncode, importBinData, TBinData } from '../../utils';

type TCPLCKey = 'icFabricator' | 'icType' | 'osProviderID' | 'osReleaseDate' | 'osReleaseLevel' | 'icFabricationDate'
    | 'icSerialNumber' | 'icBatchIdentifier' | 'icModuleFabricator' | 'icModulePackagingDate' | 'iccManufacturer'
    | 'icEmbeddingDate' | 'icPrePersonalizerID' | 'icPrePersonalizationDate' | 'icPrePersonalizationEquipmentID'
    | 'icPersonalizerID' | 'icPersonalizationDate' | 'icPersonalizationEquipmentID';

const CPLC_FIELDS: [TCPLCKey, number][] = [
    ['icFabricator', 2], ['icType', 2], ['osProviderID', 2], ['osReleaseDate', 2], ['osReleaseLevel', 2], ['icFabricationDate', 2],
    ['icSerialNumber', 4], ['icBatchIdentifier', 2], ['icModuleFabricator', 2], ['icModulePackagingDate', 2], ['iccManufacturer', 2],
    ['icEmbeddingDate', 2], ['icPrePersonalizerID', 2], ['icPrePersonalizationDate', 2], ['icPrePersonalizationEquipmentID', 4],
    ['icPersonalizerID', 2], ['icPersonalizationDate', 2], ['icPersonalizationEquipmentID', 4]
]

const CPLC_TOTAL_LEN: number = CPLC_FIELDS.reduce((acc, val) => {
    return acc + val[1];
}, 0)

type TCPLCData = { [key in TCPLCKey]: string }



export interface IGPInfo {
    /** Issuer Security Domain */
    isd?: string;
    gpVersion?: string;
    /** Max length of data field in bytes if the command APDU */
    maxCmdDataLen?: number;
    /** Application Production Life Cycle data */
    aplc?: string;
    /** List of supported scp protocols and corresponding options ("i") */
    scp?: {
        [key: string]: number[];
    };
    /** Information about the card and chip implementation, such as the operating system/runtime environment or a security kernel */
    cardAndChipInfo?: string[];
    /** Issuer Identification Number  */
    iin?: string;
    /**  Card Image Number */
    cin?: string;
    /** Card Production Life Cycle data */
    cplc?: TCPLCData;
    /** Card unique identifier. Concatenation of CPLC fields: `ICFabricator` | `ICType` | `ICBatchIdentifier` | `ICSerialNumber` */
    cuid?: string;
}

/** Gets available GlobalPlatform data from a default applet and calls provided callback upon completion. */
export function getInfo(card: ICard, callback: (err: any, info: IGPInfo) => void): void
/** Gets available GlobalPlatform data from a default applet and resolves upon completion. */
export function getInfo(card: ICard): Promise<IGPInfo>
/** Gets available GlobalPlatform data from a default applet and calls provided callback or resolves upon completion. */
export function getInfo(
    card: ICard,
    callback?: ((error: any, info: IGPInfo) => void),
): void | Promise<IGPInfo> {

    if (typeof callback === 'undefined') {
        return getInfoFromAid(card, []);
    } else {
        getInfoFromAid(card, [], callback);
    }
}

/** Gets available GlobalPlatform data from a given applet and calls provided callback upon completion. Empty aid means default applet will be used. */
export function getInfoFromAid(card: ICard, aid: TBinData, callback: (err: any, info: IGPInfo) => void): void
/** Gets available GlobalPlatform data from a given applet and resolves upon completion. Empty aid means default applet will be used. */
export function getInfoFromAid(card: ICard, aid: TBinData): Promise<IGPInfo>
/** Gets available GlobalPlatform data from a given applet and calls provided callback or resolves upon completion. Empty aid means default applet will be used.*/
export function getInfoFromAid(
    card: ICard,
    aid: TBinData,
    callback?: ((error: any, info: IGPInfo) => void),
): void | Promise<IGPInfo> {
    const importedAid = importBinData(aid);
    Logger.trace(`Getting GP info from ${ !importedAid.byteLength ? 'default applet' : `applet "${hexEncode(importedAid)}"` } ...`);
    if (typeof callback === 'undefined') {
        return new Promise((resolve, reject) => {
            const callback = (error: any, info: IGPInfo) => {
                if (typeof error !== 'undefined') {
                    return reject(error);
                }
                return resolve(info);
            };
            try {
                getInfoInternal(card, importedAid, callback);
            } catch (error: any) {
                return reject(error);
            }
        });
    } else {
        try {
            getInfoInternal(card, importedAid, callback);
        } catch (error: any) {
            callback(error, {});
        }
    }
}

function getInfoInternal(card: ICard, aid: Uint8Array, callback: (err: any, info: IGPInfo) => void): void {
    const cardInfoResult: IGPInfo = {};
    Logger.trace('Selecting applet...');
    card.issueCommand(isoSelect(aid))
        .then((selectResponse) => {
            // parsing response to default select and getting ISD AID
            if (!selectResponse.isOk || selectResponse.dataLength < 1) {
                return Promise.reject(new Error(`Error response to select: ${selectResponse.toString()}(${selectResponse.meaning})`));
            }

            let responseBer: BerObject;
            try {
                responseBer = BerObject.parse(selectResponse.data);
            } catch (error: any) {
                return Promise.reject(new Error(`Error parsing select response: ${error.message}; Data:[${hexEncode(selectResponse.data)}]`));
            }

            if (Logger.isAtLeastLevel(Logger.ELogLevel.DEBUG)) {
                responseBer.print((line) => {
                    Logger.debug(line);
                });
            }

            let tagSearchResult: BerObject[];
            tagSearchResult = responseBer.search('/6f/84');
            if (tagSearchResult.length === 1 && tagSearchResult[0].isPrimitive()) {
                cardInfoResult.isd = hexEncode(tagSearchResult[0].value);
                Logger.debug(`Detected ISD: [${cardInfoResult.isd}]`);
            }

            tagSearchResult = responseBer.search('/6f/a5/9f6e');
            if (tagSearchResult.length === 1 && tagSearchResult[0].isPrimitive()) {
                cardInfoResult.aplc = hexEncode(tagSearchResult[0].value);
                Logger.debug(`App Life Cycle (APLC): [${cardInfoResult.aplc}]`);
            }

            tagSearchResult = responseBer.search('/6f/a5/9f65');
            if (tagSearchResult.length === 1 && tagSearchResult[0].isPrimitive()) {
                hexDecode(hexEncode(tagSearchResult[0].value).padStart(8, '0'));
                cardInfoResult.maxCmdDataLen = new Uint32Array(hexDecode(hexEncode(tagSearchResult[0].value).padStart(8, '0')).reverse().buffer)[0];
                Logger.debug(`Max CMD data len: ${cardInfoResult.maxCmdDataLen} bytes`);
            }

            return Promise.resolve();
        })
        .then(() => {
            Logger.trace('Reading card recognition data...');
            return new Promise<void>((resolve) => {
                card.issueCommand(gpGetData(0x00, 0x66))
                    .then((getDataResponse) => {
                        if (!getDataResponse.isOk || getDataResponse.dataLength < 1) {
                            const errMsg = `Error response to GET_DATA (tag 0x66): ${getDataResponse.toString()}(${getDataResponse.meaning})`;
                            Logger.debug(errMsg);
                            return resolve();
                        }

                        let responseBer: BerObject;
                        try {
                            responseBer = BerObject.parse(getDataResponse.data);
                        } catch (error: any) {
                            const errMsg = `Error parsing GET_DATA response (tag 0x66): ${error.message}; Data:[${hexEncode(getDataResponse.data)}]`;
                            Logger.debug(errMsg);
                            return resolve();
                        }

                        if (Logger.isAtLeastLevel(Logger.ELogLevel.DEBUG)) {
                            responseBer.print((line) => {
                                Logger.debug(line);
                            });
                        }

                        /** Card recognition data */
                        const cardRecData = responseBer.search('/66/73');

                        if (cardRecData.length !== 1) {
                            const errMsg = 'Unexpected data';
                            Logger.warn(errMsg);
                            return resolve();
                        }

                        if (responseBer.search('/66/73/06').length !== 1) {
                            const errMsg = 'Missing mandatory globalPlatform OID tag (73/06).'
                            Logger.warn(errMsg);
                            return resolve();
                        }

                        (cardRecData[0].value as BerObject[]).forEach((cardRecDataElem) => {
                            // console.log(`reading tag "${cardRecDataTag.tag.hex}"`);
                            if (cardRecDataElem.tag.hex === '06') { // 1.2.840.114283.1
                                const oid = Asn1Utils.decodeOID(cardRecDataElem.value as Uint8Array);
                                Logger.debug(`Global Platform OID: [${oid.join('.')}]`);
                                return;
                            }

                            if (!cardRecDataElem.isConstructed() || cardRecDataElem.value.length < 1) {
                                Logger.warn(`Unexpected structure of tag "${cardRecDataElem.tag.hex}"`);
                                return;
                            }

                            const isInternalValueValid = cardRecDataElem.value.reduce((isValidValue, internalObj) => {
                                if (!isValidValue)
                                    return false;

                                if (internalObj.tag.hex !== '06')
                                    return false;

                                return true;
                            }, true)

                            if (!isInternalValueValid) {
                                Logger.warn(`Unexpected structure of tag "${cardRecDataElem.tag.hex}"`);
                                return;
                            }

                            let decodedOid: number[];
                            let oidStr: string;
                            let oidStrPrefix = '';

                            try {
                                switch (cardRecDataElem.tag.hex) {
                                    case '60': // 1.2.840.114283.2.<gpVersion>
                                    oidStrPrefix = `${GP_OID_STR}.2.`;
                                        decodedOid = Asn1Utils.decodeOID(cardRecDataElem.value[0].value as Uint8Array);
                                        oidStr = decodedOid.join('.');
                                        Logger.debug(`GP version OID: [${oidStr}]`);
                                        if (oidStr.startsWith(oidStrPrefix))
                                            cardInfoResult.gpVersion = oidStr.substring(oidStrPrefix.length);
                                        break;
                                    case '63': // 1.2.840.114283.3
                                        // Indicates a GP card that is uniquely identified by the Issuer Identification Number (IIN) and Card Image Number (CIN)
                                        break;
                                    case '64': // 1.2.840.114283.4.<scpVersion>.<i>
                                        // Secure Channel Protocol and implementation options. 2 possible formats: multiple '64' or miltiple internal '06'
                                        oidStrPrefix = `${GP_OID_STR}.4.`;
                                        cardRecDataElem.value.forEach((oid) => {
                                            const scpOid = Asn1Utils.decodeOID(oid.value as Uint8Array);
                                            const scpOidStr = scpOid.join('.');
                                            Logger.debug(`SCP OID: [${scpOidStr}]`);
                                            if (scpOidStr.startsWith(oidStrPrefix) && scpOid.length === 7) {
                                                const scpName = hexEncode([scpOid[5]]);
                                                if (typeof cardInfoResult.scp === 'undefined')
                                                    cardInfoResult.scp = {};
                                                if (typeof cardInfoResult.scp[scpName] === 'undefined')
                                                    cardInfoResult.scp[scpName] = [];
                                                cardInfoResult.scp[scpName].push(scpOid[6]);
                                            }
                                        })
                                        break;
                                    case '65':
                                        // GlobalPlatform implementation details or commonly used Card Issuer options. Such information shall be TLV encoded. The structure of this data object is under definition by GlobalPlatform.
                                        break;
                                    case '66':
                                        // This data object may contain information about the card and chip implementation, such as the operating system/runtime environment or a security kernel. Such information shall be TLV encoded and may consist of one (or more) OID(s), each OID being introduced by tag '06' and indicating the organization responsible for specifying the operating system, runtime environment or security kernel, and the identification of the corresponding specification and its version number.
                                        cardRecDataElem.value.forEach((oidObj) => {
                                            if (oidObj.tag.hex !== '06')
                                                return;
                                            if (typeof cardInfoResult.cardAndChipInfo === 'undefined')
                                                cardInfoResult.cardAndChipInfo = [];

                                            const oidStr = Asn1Utils.decodeOID(oidObj.value as Uint8Array).join('.');
                                            Logger.debug(`Card & chip info OID: [${oidStr}]`);
                                            cardInfoResult.cardAndChipInfo.push(oidStr);
                                        })
                                        break;
                                    case '67':
                                        // This data object is related to the use of Secure Channel Protocol '10' and may contain information on the certification policies, certificate formats and certificate ids associated with the Issuer Security Domain’s Trust Point (TP_ISD), primarily relating to the use of a public key Secure Channel Protocol. Such information shall be TLV encoded and may consist of one (or more) OID(s).
                                        break;
                                    case '68':
                                        // This data object is related to the use of Secure Channel Protocol '10' and may contain information such as certificate types, formats and ids associated with on-card Security Domains relating to the use of a public key Secure Channel Protocol. Such information shall be TLV encoded and may consist of one (or more) OID(s).
                                        break;
                                    default:
                                        break;
                                }
                            } catch (error: any) {
                                const errMsg = `Error reading tag "${cardRecDataElem.tag.hex}": ${error.message}`;
                                Logger.debug(errMsg);
                                return;
                            }
                        })

                        return resolve();
                    })
                    .catch((error) => {
                        const errMsg = `Error getting card data (tag 0x66): ${error.message}`;
                        Logger.debug(errMsg);
                        return resolve();
                    })
            })
        })
        .then(() => {
            Logger.trace('Reading IIN...');
            return new Promise<void>((resolve, reject) => {
                card.issueCommand(gpGetData(0x00, 0x42))
                    .then((getDataResponse) => {
                        if (hexEncode(getDataResponse.status).toLowerCase() === '6a88') {
                            return resolve();
                        }
                        if (!getDataResponse.isOk || getDataResponse.dataLength < 1) {
                            const errMsg = `Error response to GET_DATA (tag 0x42): ${getDataResponse.toString()}(${getDataResponse.meaning})`;
                            Logger.debug(errMsg);
                            return resolve();
                        }

                        let responseBer: BerObject;
                        try {
                            responseBer = BerObject.parse(getDataResponse.data);
                        } catch (error: any) {
                            const errMsg = `Error parsing response to GET_DATA (tag 0x42): ${error.message}; Data:[${hexEncode(getDataResponse.data)}]`;
                            Logger.warn(errMsg);
                            return resolve();
                        }

                        responseBer.print((line) => {
                            Logger.debug(line);
                        });

                        const iinList = responseBer.search('/42');

                        if (iinList.length !== 1) {
                            Logger.warn(`Unexpected structure of data`);
                            return resolve();
                        }

                        cardInfoResult.iin = hexEncode(iinList[0].value as Uint8Array);
                        Logger.debug(`Issuer Identification Number(IIN): [${cardInfoResult.iin}]`);
                        return resolve();
                    })
                    .catch((error) => {
                        const errMsg = `Error getting card data (tag 0x42): ${error.message}`;
                        Logger.error(errMsg);
                        return resolve();
                    });
            });
        })
        .then(() => {
            Logger.trace('Reading CIN...');
            return new Promise<void>((resolve, reject) => {
                card.issueCommand(gpGetData(0x00, 0x45))
                    .then((getDataResponse) => {
                        if (hexEncode(getDataResponse.status).toLowerCase() === '6a88') {
                            return resolve();
                        }
                        if (!getDataResponse.isOk || getDataResponse.dataLength < 1) {
                            const errMsg = `Error response to GET_DATA (tag 0x45): ${getDataResponse.toString()}(${getDataResponse.meaning})`;
                            Logger.debug(errMsg);
                            return resolve();
                        }

                        let responseBer: BerObject;
                        try {
                            responseBer = BerObject.parse(getDataResponse.data);
                        } catch (error: any) {
                            const errMsg = `Error parsing response to GET_DATA (tag 0x45): ${error.message}; Data:[${hexEncode(getDataResponse.data)}]`;
                            console.log(errMsg);
                            return resolve();
                        }

                        responseBer.print((line) => {
                            Logger.debug(line);
                        });

                        const cinList = responseBer.search('/45');

                        if (cinList.length !== 1) {
                            return resolve();
                        }

                        cardInfoResult.cin = hexEncode(cinList[0].value as Uint8Array);
                        Logger.debug(`Card Image Number(CIN): [${cardInfoResult.cin}]`);
                        return resolve();
                    })
                    .catch((error) => {
                        const errMsg = `Error getting card data (tag 0x45): ${error.message}`;
                        console.log(errMsg);
                        return resolve();
                    });
            });
        })
        .then(() => {
            Logger.trace('Reading Card Production Life Cycle (CPLC) data...');
            return new Promise<void>((resolve) => {
                card.issueCommand(gpGetData(0x9F, 0x7F))
                    .then((getDataResponse) => {
                        if (hexEncode(getDataResponse.status).toLowerCase() === '6a88') {
                            return resolve();
                        }
                        if (!getDataResponse.isOk || getDataResponse.dataLength < 1) {
                            const errMsg = `Error response to GET_DATA (tag 0x9F7F): ${getDataResponse.toString()}(${getDataResponse.meaning})`;
                            console.log(errMsg);
                            return resolve();
                        }

                        let responseBer: BerObject;
                        try {
                            responseBer = BerObject.parse(getDataResponse.data);
                        } catch (error: any) {
                            const errMsg = `Error parsing response to GET_DATA (tag 0x9F7F): ${error.message}; Data:[${hexEncode(getDataResponse.data)}]`;
                            console.log(errMsg);
                            return resolve();
                        }

                        responseBer.print((line) => {
                            Logger.debug(line);
                        });

                        const cplcList = responseBer.search('/9F7F');

                        if (cplcList.length !== 1) {
                            console.log('/9F7F')
                            return resolve();
                        }

                        const cplcData = cplcList[0].value as Uint8Array;

                        if (cplcData.byteLength !== CPLC_TOTAL_LEN) {
                            const errMsg = `Expected CPLC data to be ${CPLC_TOTAL_LEN} bytes long. Received: ${cplcData.byteLength} bytes`;
                            console.log(errMsg);
                            return resolve();
                        }

                        const cplcObj: Partial<TCPLCData> = {};

                        CPLC_FIELDS.reduce((startOffset, field) => {
                            const endOffset = startOffset + field[1];
                            cplcObj[field[0]] = hexEncode(cplcData.subarray(startOffset, endOffset));
                            Logger.debug(`${field[0]}: [${cplcObj[field[0]]}]`);
                            return endOffset;
                        }, 0);

                        cardInfoResult.cplc = cplcObj as TCPLCData;

                        cardInfoResult.cuid = `${cardInfoResult.cplc.icFabricator}${cardInfoResult.cplc.icType}${cardInfoResult.cplc.icBatchIdentifier}${cardInfoResult.cplc.icSerialNumber}`;

                        return resolve();
                    })
                    .catch((error) => {
                        const errMsg = `Error getting CPLC data (tag 0x9F7F): ${error.message}`;
                        Logger.error(errMsg);
                        return resolve();
                    });
            });
        })
        .then(() => {
            callback(undefined, cardInfoResult);
            return Promise.resolve();
        })
        .catch((error: any) => {
            callback(error, cardInfoResult)
            return;
        })
}
