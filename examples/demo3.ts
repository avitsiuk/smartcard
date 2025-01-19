import { BerObject } from '../src/ber';
import {
    PcscDevicesManager,
    Device,
    Card,
    CommandApdu,
    Utils,
    BER,
    Iso7816,
    GP,
    ResponseApdu
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

        const card = event.card;

        card.on('command-issued', (event) => {
            console.log(`[${device.name}][CMD]<< [${event.command}]`)
        })

        card.on('response-received', (event) => {
            console.log(`[${device.name}][RSP]>> [${Utils.hexEncode([...event.response.data])}][${Utils.hexEncode([...event.response.status])}](${event.response.meaning})`)
        })

        let rsp: ResponseApdu;

        try {
            rsp = await card.issueCommand(Iso7816.commands.select('429999990000'));
        } catch (error: any) {
            throw new Error(`Select error: ${error.message}`);
        }

        console.log('1:');
        try {
            rsp = await card.issueCommand(new CommandApdu('80aa1112'));
        } catch (error: any) {
            console.log(error.message)
            // throw new Error(`CMD error: ${error.message}`);
        }

        console.log('2:');
        try {
            rsp = await card.issueCommand(new CommandApdu('80aa111201'));
        } catch (error: any) {
            console.log(error.message)
            // throw new Error(`CMD error: ${error.message}`);
        }

        // console.log('3:');
        // try {
        //     rsp = await card.issueCommand(new CommandApdu('80aa111203f1f2f3'));
        // } catch (error: any) {
        //     console.log(error.message)
        //     // throw new Error(`CMD error: ${error.message}`);
        // }

        // console.log('4:');
        // try {
        //     rsp = await card.issueCommand(new CommandApdu('80aa111203f1f2f300'));
        // } catch (error: any) {
        //     console.log(error.message)
        //     // throw new Error(`CMD error: ${error.message}`);
        // }
    })
}));
