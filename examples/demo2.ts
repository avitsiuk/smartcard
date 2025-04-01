import * as v8 from 'node:v8';
import {
    Logger,
    PcscDevicesManager,
    Device,
} from '../src/index';

// example of a service resilient to pcscd restarts
// While this is running, try to restart pcscd service.
// If service restarts successfully, the device manager should
// reinit automatically without crashing.

Logger.setLogLevel(Logger.ELogLevel.TRACE); // NONE(0), FATAL(1), ERROR(2), WARN(3), INFO(4), DEBUG(5), TRACE(6)

let pcscDM: PcscDevicesManager | null = null;

function reinitDevMgr(): void {
    console.log('==> (Re)initializing device manager');
    pcscDM?.close();
    try {
        pcscDM = new PcscDevicesManager();
    } catch (error: any) {
        // pcscd service completely down.
        // potentially, one could put here some sort of timeout loop
        // to retry the whole initialization intil it succeeds
        throw new Error(`Could not instantiate device manager: ${error.message}`);
    }
    pcscDM.on('error', devMgrErrorHandler);
    pcscDM.on('device-deactivated', devRemovedHandler)
    pcscDM.on('device-activated', devAddedHandler);
}

function devMgrErrorHandler(event: { error: any, devManager: PcscDevicesManager}): void {
    console.error(`==> Device manager error: ${event.error.message}`);
    reinitDevMgr();
}

function devAddedHandler(event: {device: Device, devManager: PcscDevicesManager}): void {
    console.log(`==> Device added: ${event.device.name}`);
    event.device.on('error', (event: { error: any, device: Device }) => {
        console.error(`==> Device error: ${event.error.message}`);
    })
}

function devRemovedHandler(event: {device: Device, devManager: PcscDevicesManager}): void {
    console.log(`==> Device removed: ${event.device.name}`);
}

function sleep(time: number): Promise<void> {
    return new Promise((resolve) => {
        setTimeout(() => {
            return resolve();
        }, time);
    })
}

async function main() {
    reinitDevMgr();
    // while (true) {
    //     console.log(v8.getHeapStatistics());
    //     await sleep(1000);
    // }
}

main();
