import crypto from 'crypto';
import md5 from 'md5';
import {
    Logger as scLogger,
    PcscDevicesManager,
    Device,
    Card,
    ResponseApdu,
    BER,
    Utils,
    Iso7816Commands,
    GPUtils,
    GPCommands,
    CommandApdu,
    SCP11,
    Logger,
} from '../src/index';
import { exit } from 'process';

function importEcdsaPublicKeyFromDerSpki(pubKeyDerSpki: Buffer): crypto.KeyObject {
    return crypto.createPublicKey({key: pubKeyDerSpki, format: 'der', type: 'spki'});;
}

function importEcdsaPrivateKeyFromDerPkcs8(privKeyDerPkcs8: Buffer): crypto.KeyObject {
    return crypto.createPrivateKey({key: privKeyDerPkcs8, format: 'der', type: 'pkcs8'});
}

function derSpkiToUncompressedRaw(derSpki: Buffer): Buffer {
    return Buffer.from((BER.BerObject.parse(derSpki).search('/30/03')[0].value as Uint8Array).slice(1));
}

const caPubKeyDerSpkiBin = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004317fc92203622573eb91ab01adbe0eb5ee9ec400760c5f38eb803363b6da461c512eaa9269fe31507095eb34899d16cf18592aca56595b2bd5cc982bdf3714f9', 'hex');
const caPrivKeyDerPkcs8Bin = Buffer.from('308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104204200297a0c32a2ca73c9e52f548a98f10da37ad71c8700b8496cd2f0076c1733a14403420004317fc92203622573eb91ab01adbe0eb5ee9ec400760c5f38eb803363b6da461c512eaa9269fe31507095eb34899d16cf18592aca56595b2bd5cc982bdf3714f9', 'hex');
const caPubKey = importEcdsaPublicKeyFromDerSpki(caPubKeyDerSpkiBin);
const caPrivKey = importEcdsaPrivateKeyFromDerPkcs8(caPrivKeyDerPkcs8Bin);

function createCertificate(subjEcdhPubKeyRawUncompressed: Utils.TBinData): Buffer {
    const subjPubKey = Utils.importBinData(subjEcdhPubKeyRawUncompressed);
    const certTBSData: BER.IBerObjInfo = {
        tag: BER.Tag.root,
        value: [
            { tag: '93', value: crypto.randomBytes(16) },
            { tag: '42', value: md5(derSpkiToUncompressedRaw(caPubKeyDerSpkiBin)) },
            { tag: '5f20', value: md5(subjPubKey) },
            { tag: '95', value: '0080' },
            { tag: '5f25', value: '20250101' },
            { tag: '5f24', value: '20350101' },
            { tag: '53', value: '' },
            { tag: '5f49', value: subjEcdhPubKeyRawUncompressed },
        ]
    }
    const signature = crypto.sign(null, BER.BerObject.serialize(certTBSData), caPrivKey);
    let cardCert: BER.IBerObjInfo = {tag:BER.Tag.root,value:[{tag:'7f21',value:[...(certTBSData.value as BER.IBerObjInfo[]),{tag:'5f37',value:signature}]}]};
    return Buffer.from(BER.BerObject.serialize(cardCert));
}


function isValidCertificate(gpCert: Utils.TBinData): boolean {
    const cert = Utils.importBinData(gpCert);
    let signature: Uint8Array = new Uint8Array(0);
    const certTbsDataElems = (BER.BerObject.parse(cert).search('/7f21')[0].value as BER.IBerObjInfo[]).filter((tbsDataElem) => {
        if (tbsDataElem.tag.toString() === '5f37') {
            signature = tbsDataElem.value as Uint8Array;
            return false;
        }
        return true
    });
    const certTbsData = BER.BerObject.serialize({tag: BER.Tag.root, value: certTbsDataElems});
    return crypto.verify(null, certTbsData, caPubKey, signature);
}

async function initCard(card: Card): Promise<void> {
    let rsp: ResponseApdu;

    // Getting card static public ecdh key
    try {
        rsp = await card.issueCommand(new CommandApdu('80860000'));
    } catch (error: any) {
        throw new Error(`Error: ${error.message}`);
    }
    if (!rsp.isOk) {
        throw new Error("Could not get card static public key");
    }
    const cardEcdhStaticPubKey = (BER.BerObject.parse(rsp.data).search('/5f49')[0].value as Uint8Array);

    // creating certificate for card static public ecdh key
    // and signing it with CA ecdsa private key
    const cardCert = createCertificate(cardEcdhStaticPubKey);

    // loading CA public ecdsa key to the card
    try {
        const putKeyCommand = new CommandApdu('80d80000').setData(derSpkiToUncompressedRaw(caPubKeyDerSpkiBin));
        rsp = await card.issueCommand(putKeyCommand);
    } catch (error: any) {
        throw new Error(`Error: ${error.message}`);
    }
    if (!rsp.isOk) {
        throw new Error("Could not load CA public key to card");
    }

    // loading certificate on the card
    try {
        rsp = await card.issueCommand(new CommandApdu('80e2bf21').setData(cardCert));
    } catch (error: any) {
        throw new Error(`Error: ${error.message}`);
    }
    if (!rsp.isOk) {
        throw new Error("Could not load certificate");
    }
    return;
}


scLogger.setLogLevel(scLogger.ELogLevel.TRACE);

const devices: {[key: string]: {device: Device, card: Card | null}} = {};

function printDeviceList() {
    console.clear();
    console.log('============================================');
    const names = Object.keys(devices);

    const maxNameLen = names.reduce((currMaxLen, name) => {
        return Math.max(currMaxLen, name.length);
    }, 0)

    names.reduce((_, name) => {
        console.log(`${name.padEnd(maxNameLen, ' ')}: ${devices[name].card ? devices[name].card.atrHex : 'no card'}`)
        return null;
    }, null)

    console.log('============================================');
};

const pcscDM = new PcscDevicesManager();

console.log('============================================================');

pcscDM.on('error', (event) => {
    console.error(`Device manager error: ${event.error.message}`);
})

pcscDM.on('device-deactivated', (event) => {
    delete devices[event.device.name];
    printDeviceList();
})

pcscDM.on('device-activated', (event => {

    const device = event.device;

    devices[event.device.name] = {device: event.device, card: null};
    printDeviceList();

    device.on('error', (error) => {
        console.error(`Device error: ${error.message}`);
    })

    device.on('card-removed', (event) => {
        devices[device.name].card = null;
        printDeviceList();
    })

    device.on('card-inserted', async (event) => {
        devices[device.name].card = event.card;
        printDeviceList();

        const card = event.card;

        card.on('command-issued', (event) => {
            console.log(`[${device.name}][CMD]<< [${event.command}]`)
        });

        card.on('response-received', (event) => {
            console.log(`[${device.name}][RSP]>> [${Utils.hexEncode([...event.response.data])}][${Utils.hexEncode([...event.response.status])}](${event.response.meaning})`)
        });

        let rsp: ResponseApdu;

        // SELECT APPLET
        try {
            rsp = await card.issueCommand(Iso7816Commands.select("429999990000"));
        } catch (error: any) {
            throw new Error(`Select error: ${error.message}`);
        }
        if (!rsp.isOk) {
            throw new Error("Could not select applet");
        }

        await initCard(card);

        exit(0);
    })
}));
