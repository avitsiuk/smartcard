import {
    PcscDevicesManager,
    Device,
    Card,
    CommandApdu,
    Utils,
    BER,
    Iso7816,
    GP
} from '../src/index';

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

        console.log(Utils.decodeAtr(event.card.atr));

        console.log('Selecting default applet...');
        console.log();

        event.card.on('command-issued', (event) => {
            console.log(`[${device.name}][CMD]<< [${event.command}]`)
        })

        event.card.on('response-received', (event) => {
            console.log(`[${device.name}][RSP]>> [${Utils.hexEncode([...event.response.data])}][${Utils.hexEncode([...event.response.status])}](${event.response.meaning})`)
        })

        // Uncomment this to disable autoGetResponse feature
        // In that case GET_RESPONSE commands must be sent manually
        // event.card.autoGetResponse = false;

        // event.card.issueCommand(Iso7816Commands.select('429999990000'))
        event.card.issueCommand(Iso7816.commands.select())
            .then((selectResponse) => {
                console.log();

                let berObj: BER.BerObject | undefined;
                try {
                    berObj = BER.BerObject.parse(selectResponse.data)
                } catch (error) {
                    // decode error, probably not BER
                }

                if (berObj && selectResponse.data.byteLength > 0) {
                    console.log('Decoded card response BER:');
                    berObj.print();
                    // custom print function
                    // BER.BerObject.parse(selectResponse.data).print((obj, lvl, line) => {
                    //     console.log(`[${obj.isPrimitive() ? 'P': obj.isRoot() ? 'R' : 'C'}][${lvl}]${line}`);
                    // });
                } else {
                    console.log('Card response:');
                    console.log(`${selectResponse.toString()} (${selectResponse.meaning})`);
                }


                /*
                    Uncomment following lines to try establish a new SCP02 session
                    Note that default GP test keys are used (gpDefaultStaticKeys).
                    If card keys have been personlized, you must provide them
                    in order to successfully initiate a new secure session.
                */

                console.log();
                console.log(`Initiating SCP02 session`);

                const scp = new GP.SCP02(event.card).setStaticKeys(GP.values.defaultStaticKeys).setSecurityLevel(3);

                scp.initAndAuth()
                    .then(()=>{
                        console.log('Secure session established');
                        console.log();
                        const getCardDataCmd = new CommandApdu('80CA0066'); // getting card info. This command wil be transformed before submission
                        event.card.issueCommand(getCardDataCmd)
                            .then((cardDataResponse) => {
                                console.log(cardDataResponse);
                            })
                            .catch((error) => {
                                console.log('Error getting card info');
                                console.log(error);
                            })
                    })
                    .catch((error) => {
                        console.error('SCP02 error:');
                        console.error(error);
                        console.log();
                    })
            })
            .catch((e) => {
                console.log();
                console.error(e);
                console.log();
            })
    })
}));
