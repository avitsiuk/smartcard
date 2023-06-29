
import { defStaticKeys } from '../src/globalPlatform/secureSession';
import {
    Devices,
    Iso7816Commands,
    gpDefStaticKeys,
    GPSecureSession,
    CommandApdu,
} from '../src/index';

const pcscDevices = new Devices();

const devTypes = {
    nfc: 'NFC',
    cnt: 'CONTACT',
}

console.log('============================================================');
pcscDevices.on('device-activated', (event => {

    const device = event.device;
    let devType = 'Unknown';
    if (device.name.includes('ACR122U')) {
        devType = devTypes.nfc;
    } else if(device.name.includes('ACR39U')) {
        devType = devTypes.cnt;
    }
    console.log(`New device: ["${device.name}"](${devType})`);

    device.on('error', (error) => {
        console.error(`[${devType}] error: ${error.message}`);
    })

    device.on('card-removed', (event) => {
        if (!event.card) {
            console.log(`[${devType}]: No card inserted`);
            return;
        }
        let card = event.card;
        console.log(`[${devType}]: Removed  ${devType === devTypes.nfc ? 'ATS' : 'ATR'}:[${card.atrHex}]`);
    });

    device.on('card-inserted', async (event) => {
        if (!event.card) {
            console.log(`[${devType}]: Inserted [null]`);
            return;
        }

        let card = event.card;
        card.setAutoGetResponse();
        console.log();
        console.log(`[${devType}]: Inserted ${devType === devTypes.nfc ? 'ATS' : 'ATR'}:[${card.atrHex}]`);

        card.on('command-issued', ({ card, command }) => {
            console.log(`[${devType}]: CMD: [${command}]`);
        });

        card.on('response-received', ({ card, command, response }) => {
            console.log(`[${devType}]: RSP: [${response}](${response.meaning()})`);
        });

        console.log('=========================================================');

        // initializing new secure session and authenticating host

        const secSession = new GPSecureSession(card)
            .setStaticKeys(defStaticKeys)
            .setSecurityLevel(3);

        secSession.initAndAuth()
            .then(async(resp) => {
                console.log('===================================');
                console.log('Authenticated to ISD');
                console.log('===================================');
                let cmd1 = new CommandApdu('80E60C001A0511223344550611223344550006112233445500010202c9000000'); // install 112233445500
                let cmd2 = new CommandApdu('80E40000084F0611223344550000'); // delete 112233445500
                let cmd3 = new CommandApdu('80F210000A4F001E3C2FDD87FD86A000'); // get status
                let cmd4 = new CommandApdu('80F28002024F0000');

                const cmd = secSession.authenticator(cmd3);
                await card.issueCommand(cmd);
            })
            .catch((err) => {
                console.log('===================================');
                console.log(`Error: ${err}`);
                console.log('===================================');
            })
    });
}));

// const d = (data: number[]) => {
//     let result: any;
//     try {
//         result = sd(data);
//     } catch (error) {
//         return arrayToHex(data);
//     }
//     const keys = Object.keys(result);
//     for (let i = 0; i < keys.length; i++) {
//         const tag = keys[i];
//         if (result[tag].length > 0) {
//             result[tag].value = d(result[tag].value);
//         }
//     }
//     return result;
// }

// const tlv = d(sResp.data);

// console.log(JSON.stringify(tlv, null, 2));

// const printTlv = (tlv: any, i: number = 0) => {
//     let msg = '';
//     msg = '';
//     const tags = Object.keys(tlv);
//     for (let tragIdx = 0; tragIdx < tags.length; tragIdx++) {
//         const tag = tags[tragIdx];
//         msg = `[${tag}](${tlv[tag].length}):`;

//         if (typeof tlv[tag].value === 'string') {
//             msg += ` [${tlv[tag].value.toUpperCase()}]`;
//             console.log(msg.padStart((msg.length + (4 * i)), ' '));
//         } else {
//             console.log(msg.padStart((msg.length + (4 * i)), ' '));
//             printTlv(tlv[tag].value, ++i);
//         }
//     }
// };