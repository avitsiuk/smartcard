import { hexEncode, hexDecode } from '../utils';
// import ResponseApdu from "../responseApdu";
import { type TIssueCommandPromiseFunction} from '../typesInternal';
import * as EmvValues from './values';
import * as Iso7816Commands from '../iso7816/commands';
import { BerObject } from '../ber';
import ResponseApdu from '../responseApdu';
import Logger from '../logger';

export async function getAppList(issueCommand: TIssueCommandPromiseFunction): Promise<void> {
    return new Promise((resolve, reject) => {
        issueCommand(Iso7816Commands.select(EmvValues.PSE2_AID))
            .then((resp) => {
                const parsedPse = BerObject.parse(resp.data);
                if (Logger.isAtLeastLevel(Logger.ELogLevel.DEBUG)) {
                    parsedPse.print((line) => {
                        Logger.debug(line);
                    });
                }
                const appList = parsedPse.search('/6f/a5/bf0c/61');
                for (let appIdx = 0; appIdx < appList.length; appIdx++) {
                    console.log('=======');
                    const app = appList[appIdx];
                    if (!app.isConstructed()) continue;
                    for (const appData of app.value) {
                        if (!appData.isPrimitive()) continue;
                        switch (appData.tag.hex) {
                            case '4f': // aid
                                console.log(`aid: ${hexEncode(appData.value)}`);
                                break;
                            case '50': // label
                                console.log(`label: ${new TextDecoder().decode(appData.value)}`);
                                break;
                            case '87': // priority
                                console.log(`priority: ${hexEncode(appData.value)}`);
                                break;
                            case '9f12': // preferred name
                                console.log(`preferred name: ${new TextDecoder().decode(appData.value)}`);
                                break;
                            case '9f11': // code table
                                console.log(`code table: ${hexEncode(appData.value)}`);
                                break;
                            case '5f2d': // lang
                                console.log(`lang: ${new TextDecoder().decode(appData.value)}`);
                                break;
                            case '9f0a': // proprietary data
                                break;
                            default:
                                break;
                        }
                    }
                }
                return resolve();
            })
            .catch((error) => {
                return reject(error);
            });
    })

    // const appList = parsedPse.search('/6f/a5/bf0c/61');
    // for (let appIdx = 0; appIdx < appList.length; appIdx++) {
    //     const app = appList[appIdx];
    //     if (app.isConstructed()) {
    //         // aid(4f), label(50), priority(87), preferred name(9f12), code table(9f11), lang(5f2d), proprietary data(9f0a)
    //         let aid: Uint8Array;
    //         const label: string | null = null;

    //         const aidTags = app.search('/4f');
    //         if (aidTags.length < 1) {
    //             continue;
    //         }
    //         const aid = aidTags[0].value as Uint8Array;

    //         const labelTags = app.search('/50');

    //         if (nameTags.length > 0) {
    //             console.log(`name: ${new TextDecoder().decode(nameTags[0].value as Uint8Array)}`);
    //         }
    //         console.log(`aid: ${Utils.hexEncode(aidTags[0].value as Uint8Array)}`);
    //     }
    // }
}