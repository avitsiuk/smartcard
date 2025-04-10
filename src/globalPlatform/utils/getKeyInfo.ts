import Logger from '../../logger';
import { ICard } from '../../typesInternal';
import { BerObject } from '../../ber';
import { select as isoSelect } from '../../iso7816/commands';
import { getData as gpGetData } from './../commands';
import { EKeyType } from './../values';
import { hexEncode, importBinData, TBinData } from '../../utils';

export interface IGPKeyInfo {
    [key: number]: {
        /** Key (component) version number */
        version: number;
        /** Key (component) type */
        type: keyof typeof EKeyType;
        /** Key (component) length in bytes */
        length: number;
    };
}

/** Gets available GlobalPlatform key data from a default applet and calls provided callback upon completion. */
export function getKeyInfo(
    card: ICard,
    callback: (err: any, info: IGPKeyInfo) => void,
): void;
/** Gets available GlobalPlatform key data from a default applet and resolves upon completion. */
export function getKeyInfo(card: ICard): Promise<IGPKeyInfo>;
/** Gets available GlobalPlatform key data from a default applet and calls provided callback or resolves upon completion. */
export function getKeyInfo(
    card: ICard,
    callback?: (error: any, info: IGPKeyInfo) => void,
): void | Promise<IGPKeyInfo> {
    if (typeof callback === 'undefined') {
        return getKeyInfoFromAid(card, []);
    } else {
        getKeyInfoFromAid(card, [], callback);
    }
}

/** Gets available GlobalPlatform key data from a given applet and calls provided callback upon completion. Empty aid means default applet will be used. */
export function getKeyInfoFromAid(
    card: ICard,
    aid: TBinData,
    callback: (err: any, info: IGPKeyInfo) => void,
): void;
/** Gets available GlobalPlatform key data from a given applet and resolves upon completion. Empty aid means default applet will be used. */
export function getKeyInfoFromAid(
    card: ICard,
    aid: TBinData,
): Promise<IGPKeyInfo>;
/** Gets available GlobalPlatform key data from a given applet and calls provided callback or resolves upon completion. Empty aid means default applet will be used.*/
export function getKeyInfoFromAid(
    card: ICard,
    aid: TBinData,
    callback?: (error: any, info: IGPKeyInfo) => void,
): void | Promise<IGPKeyInfo> {
    const importedAid = importBinData(aid);
    Logger.trace(
        `Getting GP key info from ${!importedAid.byteLength ? 'default applet' : `applet "${hexEncode(importedAid)}"`} ...`,
    );
    if (typeof callback === 'undefined') {
        return new Promise((resolve, reject) => {
            const callback = (error: any, info: IGPKeyInfo) => {
                if (typeof error !== 'undefined') {
                    return reject(error);
                }
                return resolve(info);
            };
            try {
                getKeyInfoInternal(card, importedAid, callback);
            } catch (error: any) {
                return reject(error);
            }
        });
    } else {
        try {
            getKeyInfoInternal(card, importedAid, callback);
        } catch (error: any) {
            callback(error, {});
        }
    }
}

function getKeyInfoInternal(
    card: ICard,
    aid: Uint8Array,
    callback: (err: any, info: IGPKeyInfo) => void,
): void {
    const keyInfoResult: IGPKeyInfo = {};
    Logger.trace('Selecting applet...');
    card.issueCommand(isoSelect(aid))
        .then((selectResponse) => {
            // parsing response to default select and getting ISD AID
            if (!selectResponse.isOk || selectResponse.dataLength < 1) {
                return Promise.reject(
                    new Error(
                        `Error response to select: ${selectResponse.toString()}(${selectResponse.meaning})`,
                    ),
                );
            }

            return Promise.resolve();
        })
        .then(() => {
            Logger.trace('Reading key data...');
            return new Promise<void>((resolve) => {
                card.issueCommand(gpGetData(0x00, 0xe0))
                    .then((getDataResponse) => {
                        if (
                            !getDataResponse.isOk ||
                            getDataResponse.dataLength < 1
                        ) {
                            const errMsg = `Error response to GET_DATA (tag 0xE0): ${getDataResponse.toString()}(${getDataResponse.meaning})`;
                            Logger.debug(errMsg);
                            return resolve();
                        }

                        let responseBer: BerObject;
                        try {
                            responseBer = BerObject.parse(getDataResponse.data);
                        } catch (error: any) {
                            const errMsg = `Error parsing GET_DATA response (tag 0xE0): ${error.message}; Data:[${hexEncode(getDataResponse.data)}]`;
                            Logger.debug(errMsg);
                            return resolve();
                        }

                        if (Logger.isAtLeastLevel(Logger.ELogLevel.DEBUG)) {
                            responseBer.print((line) => {
                                Logger.debug(line);
                            });
                        }

                        return resolve();
                    })
                    .catch((error) => {
                        const errMsg = `Error getting card data (tag 0xE0): ${error.message}`;
                        Logger.debug(errMsg);
                        return resolve();
                    });
            });
        })
        .then(() => {
            callback(undefined, keyInfoResult);
            return Promise.resolve();
        })
        .catch((error: any) => {
            callback(error, keyInfoResult);
            return;
        });
}
