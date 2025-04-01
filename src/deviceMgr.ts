import { EventEmitter } from 'events';
import pcsclite from 'pcsclite';
import Logger from './logger';
import { CardReader, PCSCLite } from './typesPcsclite';
import { IDevicesManager, TDevicesManagerEventName } from './typesInternal';
import Device from './device';

export class PcscDevicesManager implements IDevicesManager {
    private _eventEmitter: EventEmitter;
    private pcsc: PCSCLite;
    private _devices: { [key: string]: Device };

    constructor() {
        Logger.trace('Instantiating new PCSC device manager');
        this._eventEmitter = new EventEmitter();
        this._devices = {};
        try {
            this.pcsc = pcsclite();
        } catch (error: any) {
            const errMsg = `PCSCLite error: ${error.message}`;
            Logger.fatal(errMsg);
            throw new Error(errMsg);
        }
        this.pcsc.on('reader', (reader: CardReader) => {
            Logger.trace(
                `Emitted PCSCLite "reader" event. Reader name: "${reader.name}"`,
            );
            const device = new Device(reader);
            this._devices[reader.name] = device;
            this._eventEmitter.emit('device-activated', {
                device,
                devices: this.devices,
            });
            reader.on('end', () => {
                Logger.trace(
                    `Emitted "end" event for device: "${reader.name}"`,
                );
                delete this._devices[reader.name];
                this._eventEmitter.emit('device-deactivated', {
                    device,
                    devices: this.devices,
                });
            });
        });

        this.pcsc.on('error', (error) => {
            Logger.trace('Emitted PCSCLite "error" event');
            this._eventEmitter.emit('error', { error, devManager: this });
        });
    }

    close(): void {
        Logger.trace('Closing PCSCLite');
        this.pcsc.close();
    }

    /** List of all currently connected devices */
    get devices(): { [key: string]: Device } {
        return this._devices;
    }

    /** Resolved upon `device-activated` event */
    onActivated(): Promise<{ device: Device; devManager: IDevicesManager }> {
        return new Promise((resolve, reject) => {
            this.once('device-activated', (event) => resolve(event));
        });
    }

    /** Resolved upon `device-deactivated` event */
    onDeactivated(): Promise<{ device: Device; devManager: IDevicesManager }> {
        return new Promise((resolve, reject) => {
            this.once('device-deactivated', (event) => resolve(event));
        });
    }

    /** Returns device under a given name (if any)
     * @param name - device name to lookup
     */
    lookup(name: string): Device | null {
        if (this._devices[name]) {
            return this._devices[name];
        }
        return null;
    }

    /** Emitted when a new device is detected */
    on(
        eventName: 'device-activated',
        eventHandler: (event: {
            device: Device;
            devManager: PcscDevicesManager;
        }) => void,
    ): PcscDevicesManager;
    /** Emitted when a device gets disconnected */
    on(
        eventName: 'device-deactivated',
        eventHandler: (event: {
            device: Device;
            devManager: PcscDevicesManager;
        }) => void,
    ): PcscDevicesManager;
    on(
        eventName: 'error',
        eventHandler: (event: {
            error: any;
            devManager: PcscDevicesManager;
        }) => void,
    ): PcscDevicesManager;
    on(
        eventName: TDevicesManagerEventName,
        eventHandler: (event: any) => void,
    ): PcscDevicesManager {
        this._eventEmitter.on(eventName, eventHandler);
        return this;
    }

    /** Emitted when a new device is detected */
    once(
        eventName: 'device-activated',
        eventHandler: (event: {
            device: Device;
            devManager: PcscDevicesManager;
        }) => void,
    ): PcscDevicesManager;
    /** Emitted when a device gets disconnected */
    once(
        eventName: 'device-deactivated',
        eventHandler: (event: {
            device: Device;
            devManager: PcscDevicesManager;
        }) => void,
    ): PcscDevicesManager;
    once(
        eventName: 'error',
        eventHandler: (event: {
            error: any;
            devManager: PcscDevicesManager;
        }) => void,
    ): PcscDevicesManager;
    once(
        eventName: TDevicesManagerEventName,
        eventHandler: (event: any) => void,
    ): PcscDevicesManager {
        this._eventEmitter.on(eventName, eventHandler);
        return this;
    }

    removeListener(
        eventName: TDevicesManagerEventName,
        eventHandler: (...args: any[]) => void,
    ): void {
        this._eventEmitter.removeListener(eventName, eventHandler);
    }

    off(
        eventName: TDevicesManagerEventName,
        eventHandler: (...args: any[]) => void,
    ): void {
        this.removeListener(eventName, eventHandler);
    }

    removeAllListeners(eventName: TDevicesManagerEventName): void {
        this._eventEmitter.removeAllListeners(eventName);
    }
}

export default PcscDevicesManager;
