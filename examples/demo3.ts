import {
    Logger,
    PcscDevicesManager,
    Device,
    Card,
    // CommandApdu,
    Utils,
    BER,
    Iso7816Commands,
    // GPCommands,
    GPUtils,
    SCP11,
    // ResponseApdu,
} from '../src/index';

Logger.setLogLevel(Logger.ELogLevel.INFO); // NONE(0), FATAL(1), ERROR(2), WARN(3), INFO(4), DEBUG(5), TRACE(6)

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

    device.on('error', (event) => {
        console.error(`Device error: ${event.error.message}`);
    })

    device.on('card-removed', (_event) => {
        devices[device.name].card = null;
        printDeviceList();
    })

    device.on('card-inserted', async (event) => {
        devices[device.name].card = event.card;
        printDeviceList();

        const card = event.card;

        // logging card communications
        event.card.on('command-issued', (event) => {
            console.log(`[${event.device.name}][CMD]<< [${event.command}]`)
        })
        event.card.on('response-received', (event) => {
            console.log(`[${event.device.name}][RSP]>> [${Utils.hexEncode([...event.response.data])}][${Utils.hexEncode([...event.response.status])}](${event.response.meaning})`)
        })

        // console.log(Utils.decodeAtr(card.atr));

        console.log('Selecting applet...');
        // console.log();

        // Uncomment this to disable autoGetResponse feature
        // In that case GET_RESPONSE commands must be sent manually
        // event.card.autoGetResponse = false;

        event.card.issueCommand(Iso7816Commands.select('429999990000'))
            .then((selectResponse) => {
                if (!selectResponse.isOk) throw new Error('Could not select applet');
            })
            .then(() => {
                return new SCP11(event.card).mutAuth();

                // // get info from a GlobalPlatform card
                // return GPUtils.getInfo(card);
            })
            .then(() => {
                // console.log();
                // console.log('Card info:')
                // console.log(cardInfo);
            })
            .catch((e) => {
                console.log('==ERR==');
                console.error(e);
                console.log('=======');
            })
    })
}));
