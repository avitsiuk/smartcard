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
import { hexEncode } from '../src/utils';

function generateEcdsaKeyPair(): crypto.KeyPairKeyObjectResult {
    return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

function exportEcdsaPublicKeyToDerSpki(pubKey: crypto.KeyObject): Buffer {
    return pubKey.export({ format: 'der', type: 'spki' });
}

function exportEcdsaPrivateKeyToDerPkcs8(privKey: crypto.KeyObject): Buffer {
    return privKey.export({ format: 'der', type: 'pkcs8' });
}

function importEcdsaPublicKeyFromDerSpki(pubKeyDerSpki: Buffer): crypto.KeyObject {
    return crypto.createPublicKey({key: pubKeyDerSpki, format: 'der', type: 'spki'});;
}

function importEcdsaPrivateKeyFromDerPkcs8(privKeyDerPkcs8: Buffer): crypto.KeyObject {
    return crypto.createPrivateKey({key: privKeyDerPkcs8, format: 'der', type: 'pkcs8'});
}

function derSpkiToUncompressedRaw(derSpki: Buffer): Buffer {
    return Buffer.from((BER.BerObject.parse(derSpki).search('/30/03')[0].value as Uint8Array).slice(1));
}

function uncompressedRawToDerSpki(uncompressedRaw: Buffer) {
    const berObj: BER.IBerObjInfo = {
        tag: BER.Tag.root,
        value: [
            {
                tag: '30',
                value: [
                    {
                        tag: '30', value: [
                            { tag: '06', value: '2a8648ce3d0201'},
                            { tag: '06', value: '2a8648ce3d030107' },
                        ]
                    },
                    {
                        tag: '03',
                        value: new Uint8Array([0x00, ...uncompressedRaw]),
                    }
                ],
            },
        ]
    }
    return Buffer.from(BER.BerObject.serialize(berObj));
}

const caPubKeyDerSpkiBin = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004317fc92203622573eb91ab01adbe0eb5ee9ec400760c5f38eb803363b6da461c512eaa9269fe31507095eb34899d16cf18592aca56595b2bd5cc982bdf3714f9', 'hex');
const caPrivKeyDerPkcs8Bin = Buffer.from('308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104204200297a0c32a2ca73c9e52f548a98f10da37ad71c8700b8496cd2f0076c1733a14403420004317fc92203622573eb91ab01adbe0eb5ee9ec400760c5f38eb803363b6da461c512eaa9269fe31507095eb34899d16cf18592aca56595b2bd5cc982bdf3714f9', 'hex');
// const caPubKeyDerSpkiBin = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200044e6b8e76f048801e55221538f981fc5debaac18bf686d3e4e26a6a10ce3dfcb2d0059f82fa63dae30a8ee1cc581a90a4189d43a24341bf015ad8305e959c8df4', 'hex');
// const caPrivKeyDerPkcs8Bin = Buffer.from('308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104208dfe58fd280c02731f7a55f5599f4c48d5c79fc36700b8ea7513f737dd5c5abfa144034200044e6b8e76f048801e55221538f981fc5debaac18bf686d3e4e26a6a10ce3dfcb2d0059f82fa63dae30a8ee1cc581a90a4189d43a24341bf015ad8305e959c8df4', 'hex');
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


scLogger.setLogLevel(scLogger.ELogLevel.WARN);

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

        let counter: number = 0;

        let cmdHex: string = '';

        card.on('command-issued', (event) => {
            if (event.command.getIns() !== 0xc0) {
                cmdHex = event.command.toString();
            }
            // console.log(`[${device.name}][CMD]<< [${event.command}]`)
        });

        card.on('response-received', (event) => {
            if (event.response.status[0] !== 0x61) {
                counter++;
                console.log(`${counter}: [${cmdHex}] >> [${event.response.toString()}]`)
            }
            // console.log(`[${device.name}][RSP]>> [${Utils.hexEncode([...event.response.data])}][${Utils.hexEncode([...event.response.status])}](${event.response.meaning})`)
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

        // await initCard(card);

        // ============== SCP 11a ==============

        '04c19c9d4ec95bdba5a242d40226364dfecfaf6a372d10e538381576d258b78398a922f753f373c7bbda70fac6c53b053088b1ebe1a7d794fdbd8804ead3d55758'
        '00e0e90281b9448e9ddf3e9fd5bdd8a7901cc2e533cefa71b8153bb548a7e3993a'
        '7f2181da9310611b78be9c50e6c0bbf38608e11a73444210d2aa45b52e5f26aca1741d4eecb107e05f2010b82fb215a14fe3877ba0ede1a3aa704f950200805f2504202501015f24042035010153005f494104c19c9d4ec95bdba5a242d40226364dfecfaf6a372d10e538381576d258b78398a922f753f373c7bbda70fac6c53b053088b1ebe1a7d794fdbd8804ead3d557585f37483046022100d548d5530b4564b9a25c8a58bf40c43424361be1e346c65af08c13aef172baf2022100abf6e824b3ef4e2d27c34dbb2dd2f278ed06b5253f84645819d300e063ab6d35'
        '7f2181d99310f3dd67a8111e18420ff282859d032cf542105ed944d9fb5b515d8346b0daef447fcd5f2010b82fb215a14fe3877ba0ede1a3aa704f950200805f2504202501015f24042035010153005f494104c19c9d4ec95bdba5a242d40226364dfecfaf6a372d10e538381576d258b78398a922f753f373c7bbda70fac6c53b053088b1ebe1a7d794fdbd8804ead3d557585f37473045022041ac391699167f52bf3a8003d9e8f619b66f3691a52253386dde330ebef8924a022100b36bd5db2c21c8bdadf34d33eaa8eb31d0cefe8d673e91eca74d4cc6d95108d1'

        '0427f7e304222031f418a2998adc250bf9076a2e94340791476ddb9da1c0fb3592d8d4862cd7a29cc7d0963579d45df853c96f208803d11efd9e313027dbdb7c8b'
        '009f24ff3b775e07854a26f44edc175f2b21b1a6608363d69808f7b59023f10e6e'
        '7f2181d99310a7ffa2434991678bea22e8f1345b5fd84210d2aa45b52e5f26aca1741d4eecb107e05f2010a8faaf5afa522f046b05a1c931a8867f950200805f2504202501015f24042035010153005f49410427f7e304222031f418a2998adc250bf9076a2e94340791476ddb9da1c0fb3592d8d4862cd7a29cc7d0963579d45df853c96f208803d11efd9e313027dbdb7c8b5f374730450221008efe1b91b17ecf2a0e62b3b8425beaba8c60099f9312e756ae5e39538b68ffca02207f1323284307fbcacbcfb8cc52a5d6d3b0bf811c9426d714e679f25e7cad8920'
        '7f2181da931052abf42524113c43751004e6074807df42105ed944d9fb5b515d8346b0daef447fcd5f2010a8faaf5afa522f046b05a1c931a8867f950200805f2504202501015f24042035010153005f49410427f7e304222031f418a2998adc250bf9076a2e94340791476ddb9da1c0fb3592d8d4862cd7a29cc7d0963579d45df853c96f208803d11efd9e313027dbdb7c8b5f37483046022100e3fe710f9377c45896456b1a41aca7d11d6c1ab57842bc9e285c296dae8dea8d022100a113a18f32038e3a7cd0c50e71033746282c3baf3bd6b751678c76fb7ee73212'

        const oceEcdhKeyPair = crypto.createECDH('prime256v1');
        oceEcdhKeyPair.generateKeys();
        const oceEcdhStaticPubKey = oceEcdhKeyPair.getPublicKey(null, 'uncompressed');
        const oceEcdhStaticPrivKey = oceEcdhKeyPair.getPrivateKey();
        const oceCert = createCertificate(oceEcdhStaticPubKey);

        const oceEcdhKeyPair2 = crypto.createECDH('prime256v1');
        oceEcdhKeyPair2.generateKeys();
        const oceEcdhStaticPubKey2 = oceEcdhKeyPair2.getPublicKey(null, 'uncompressed');
        const oceEcdhStaticPrivKey2 = oceEcdhKeyPair2.getPrivateKey();
        const oceCert2 = createCertificate(oceEcdhStaticPubKey2);

        const scp11 = new SCP11(card)
            .setSecurityLevel(0x3C)
            .setCAEcdsaPublicKey(caPubKeyDerSpkiBin)
            .setStaticEcdhKeypair(oceEcdhStaticPubKey, oceEcdhStaticPrivKey)
            .setStaticEcdhPublicKeyCertificate(oceCert);

        try {
            await scp11.mutAuth();
        } catch (error: any) {
            exit(0);
        }

        for (let i = 0; i < 100000; i++) {
            try {
                rsp = await card.issueCommand(CommandApdu.from("80ff0000").setData('f0f1f2f3f4f5f6f7'));
            } catch (error: any) {
                throw new Error(`Debug cmd error: ${error.message}`);
            }
    
            if (!rsp.isOk) {
                throw new Error("Not OK");
            }
            // console.log(`${i+1}/${100000}`);
        }


        // const gpInfo = await GPUtils.getInfo(card);
        // console.log(JSON.stringify(gpInfo, null, 2));

        // console.log("=========================");

        // const gpCaps = await GPUtils.getCapabilitiesFromAid(card, "");
        // console.log(JSON.stringify(gpCaps, null, 2));

        // console.log("=========================");

        // const gpKeyInfo = await GPUtils.getKeyInfo(card);
        // console.log(JSON.stringify(gpKeyInfo, null, 2));

        // let rsp: ResponseApdu;

        // try {
        //     rsp = await card.issueCommand(GPCommands.getData(0x00, 0x67));
        // } catch (error: any) {
        //     throw new Error(`Select error: ${error.message}`);
        // }

        // const berObj = BER.BerObject.parse(rsp.data);

        // berObj.print();
        // // try {
        // //     rsp = await card.issueCommand(new CommandApdu('80F20000'))
        // // } catch (error: any) {
        // //     throw new Error(`Select error: ${error.message}`)
        // // }
        // // 00 a4 04 00 06 429999990000 00

        // // console.log(`${rsp.toString()}(${rsp.meaning})`);

        // // GP.Utils.gl
    })
}));
