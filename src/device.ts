import { EventEmitter } from 'events';
import Logger from './logger';
import { CardReader, Status } from './typesPcsclite';
import { IDevice, TDeviceEventName } from './typesInternal';
import { hexEncode, importBinData } from './utils';
import Card from './card';

export class Device implements IDevice {
    private _eventEmitter = new EventEmitter();
    /** Basic PSCS reader corresponding to this device */
    reader: CardReader;
    /** Name of this device */
    name: string;
    /** Currently inserted card (if any) */
    card: Card | null;

    constructor(reader: CardReader) {
        Logger.trace(`Instantiating new device: "${reader.name}"`);
        this.reader = reader;
        this.name = reader.name;
        this.card = null;

        const isCardInserted = (
            changes: number,
            reader: CardReader,
            status: Status,
        ) => {
            return (
                changes & reader.SCARD_STATE_PRESENT &&
                status.state & reader.SCARD_STATE_PRESENT
            );
        };

        const isCardRemoved = (
            changes: number,
            reader: CardReader,
            status: Status,
        ) => {
            return (
                changes & reader.SCARD_STATE_EMPTY &&
                status.state & reader.SCARD_STATE_EMPTY
            );
        };

        const cardInserted = (reader: CardReader, status: Status) => {
            Logger.trace(`Card inserted into "${this.name}"`);
            reader.connect({ share_mode: 2 }, (error, protocol) => {
                if (error) {
                    this._eventEmitter.emit('error', { error, device: this });
                } else {
                    try {
                        this.card = new Card(
                            this,
                            status.atr
                                ? importBinData(status.atr)
                                : new Uint8Array(0),
                            protocol,
                        );
                    } catch (error: any) {
                        this._eventEmitter.emit('error', {
                            error: new Error(`Card error: ${error.message}`),
                            device: this,
                        });
                        return;
                    }
                    this._eventEmitter.emit('card-inserted', {
                        device: this,
                        card: this.card,
                    });
                }
            });
        };

        const cardRemoved = (reader: CardReader) => {
            Logger.trace(`Card removed from "${this.name}"`);
            const name = reader.name;
            reader.disconnect(reader.SCARD_LEAVE_CARD, (error) => {
                if (error) {
                    this._eventEmitter.emit('error', { error, device: this });
                } else {
                    this._eventEmitter.emit('card-removed', {
                        device: this,
                        card: this.card,
                    });
                    this.card = null;
                }
            });
        };

        reader.on('error', (error) => {
            Logger.trace(`Emitted "error" event for device: "${reader.name}"`);
            this._eventEmitter.emit('error', { error, device: this });
        });

        reader.on('status', (status: Status) => {
            Logger.trace(
                `Device status change. Status: ${status.state}. Device: "${this.name}"`,
            );
            const changes = reader.state ^ status.state;
            if (changes) {
                if (isCardRemoved(changes, reader, status)) {
                    cardRemoved(reader);
                } else if (isCardInserted(changes, reader, status)) {
                    cardInserted(reader, status);
                }
            }
        });
    }

    transmit(
        data: Uint8Array,
        res_len: number,
        protocol: number,
        cb: (err: any, response: Uint8Array) => void,
    ) {
        Logger.trace(
            `Transmitting ${data.byteLength} bytes to device "${this.name}"; res_len: ${res_len}; protocol: ${protocol}`,
        );
        this.reader.transmit(
            Buffer.from(data),
            res_len,
            protocol,
            (err: any, response: Buffer) => {
                let u8Arr: Uint8Array = new Uint8Array(0);
                if (response) {
                    u8Arr = new Uint8Array(response.buffer).subarray(
                        response.byteOffset,
                        response.byteOffset + response.byteLength,
                    );
                }
                Logger.trace(
                    `Received response from device "${this.name}"; res_len: ${u8Arr.byteLength}; is_error: ${err ? true : false}; protocol: ${protocol}`,
                );
                Logger.trace(`Raw response received: [${hexEncode(u8Arr)}]`);
                cb(err, u8Arr);
            },
        );
    }

    getName() {
        return this.name;
    }

    toString() {
        return `${this.getName()}`;
    }

    on(
        eventName: 'error',
        eventHandler: (event: { error: any; device: Device }) => void,
    ): Device;
    on(
        eventName: 'card-inserted',
        eventHandler: (event: { device: Device; card: Card }) => void,
    ): Device;
    on(
        eventName: 'card-removed',
        eventHandler: (event: { device: Device; card: Card }) => void,
    ): Device;
    on(
        eventName: TDeviceEventName,
        eventHandler: (event: any) => void,
    ): Device {
        this._eventEmitter.on(eventName, eventHandler);
        return this;
    }

    once(
        eventName: 'error',
        eventHandler: (event: { error: any; device: Device }) => void,
    ): Device;
    once(
        eventName: 'card-inserted',
        eventHandler: (event: { device: Device; card: Card }) => void,
    ): Device;
    once(
        eventName: 'card-removed',
        eventHandler: (event: { device: Device; card: Card }) => void,
    ): Device;
    once(
        eventName: TDeviceEventName,
        eventHandler: (event: any) => void,
    ): Device {
        this._eventEmitter.on(eventName, eventHandler);
        return this;
    }

    removeListener(
        eventName: TDeviceEventName,
        eventHandler: (...args: any[]) => void,
    ): void {
        this._eventEmitter.removeListener(eventName, eventHandler);
    }

    off(
        eventName: TDeviceEventName,
        eventHandler: (...args: any[]) => void,
    ): void {
        this.removeListener(eventName, eventHandler);
    }

    removeAllListeners(eventName: TDeviceEventName): void {
        this._eventEmitter.removeAllListeners(eventName);
    }
}

export default Device;
