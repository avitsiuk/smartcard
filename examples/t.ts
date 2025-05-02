import {
    Logger,
    PcscDevicesManager,
    // Device,
    // Card,
    CommandApdu,
    Utils,
    BER,
    Iso7816Commands,
    // GPCommands,
    GPUtils,
    // EmvValues,
    EmvUtils,
    // ResponseApdu,
} from '../src/index';
import { TBinData } from '../src/utils';

Logger.setLogLevel(Logger.ELogLevel.INFO); // NONE(0), FATAL(1), ERROR(2), WARN(3), INFO(4), DEBUG(5), TRACE(6)

const pcscDM = new PcscDevicesManager();

pcscDM.on('error', (event) => {
    Logger.error(`Device manager error: ${event.error.message}`)
})

pcscDM.on('device-deactivated', (event) => {
    Logger.info(`Device disconnected: ${event.device.name}`);
})

pcscDM.on('device-activated', (event => {

    Logger.info(`Device connected: ${event.device.name}`);

    const device = event.device;

    device.on('error', (event) => {
        Logger.error(`Device "${event.device.name}" error: ${event.error.message}`);
    })

    device.on('card-removed', (_event) => {
        Logger.info(`Card removed from device "${event.device.name}"`);
    })

    device.on('card-inserted', async (event) => {
        Logger.info(`Card inserted into device "${event.device.name}"`);

        event.card.on('command-issued', (event) => {
            Logger.info(`[${event.device.name}][CMD]<< [${event.command}]`);
        })
        event.card.on('response-received', (event) => {
            Logger.info(`[${event.device.name}][RSP]>> [${Utils.hexEncode([...event.response.data])}][${Utils.hexEncode([...event.response.status])}](${event.response.meaning})`);
        })

        const issueCardCommandFun = (cmd: CommandApdu | TBinData) => {
            return event.card.issueCommand(cmd);
        }

        // console.log(Utils.decodeAtr(event.card.atr));
        EmvUtils.getAppList(issueCardCommandFun);

        return;

        event.card.issueCommand(Iso7816Commands.select())
            .then((selectResponse) => {
                console.log();

                let berObj: BER.BerObject | undefined;
                try {
                    berObj = BER.BerObject.parse(selectResponse.data);
                } catch (_error) {
                    // decode error, probably not BER
                }

                if (berObj && selectResponse.data.byteLength > 0) {
                    console.log('Decoded card response BER:');
                    berObj.print();
                    // // custom print function
                    // berObj.print((line, lvl, obj) => {
                    //     console.log(`[${obj.isPrimitive() ? 'P': obj.isRoot() ? 'R' : 'C'}][${lvl}]${line}`);
                    // });
                } else {
                    console.log('Card response:');
                    console.log(`${selectResponse.toString()} (${selectResponse.meaning})`);
                }
            })
            .then(() => {
                // get info from a GlobalPlatform card
                return GPUtils.getInfo(event.card);
            }).then((cardInfo) => {
                console.log();
                console.log('Card info:')
                console.log(cardInfo);
            })
            .catch((e) => {
                console.log();
                console.error(e);
                console.log();
            })
    })
}));
