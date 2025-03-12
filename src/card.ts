import { EventEmitter } from 'events';
import Logger from './logger';
import {
    hexEncode,
    type IAtrInfo,
    importBinData,
    type TBinData,
    decodeAtr,
} from './utils';
import CommandApdu from './commandApdu';
import ResponseApdu from './responseApdu';
import { type ICard, type IDevice, type TCardEventName } from './typesInternal';
import { getResponse as isoGetResponse } from './iso7816/commands';

/** Response APDU max size(256 for data + 2 for status) */
const maxTrResLen = 258;

export class Card implements ICard {
    private _isBusy: boolean;
    private _eventEmitter = new EventEmitter();
    private _device: IDevice;
    private _protocol: number;
    private _atr: Uint8Array;
    private _atrHex: string;
    private _decodedAtr: IAtrInfo | null = null;
    private _autoGetResponse: boolean = true;
    private _commandTransformer:
        | undefined
        | ((cmd: CommandApdu) => CommandApdu);
    private _responseTransformer:
        | undefined
        | ((rsp: ResponseApdu) => ResponseApdu);

    constructor(device: IDevice, atr: Uint8Array, protocol: number) {
        Logger.trace(`Creating card instance for device "${device.name}"`);
        this._device = device;
        this._protocol = protocol;
        this._atr = new Uint8Array(atr.byteLength);
        try {
            importBinData(atr, this._atr);
            this._decodedAtr = decodeAtr(this._atr);
        } catch (error: any) {
            const err = new Error(`Error importing card ATR: ${error.message}`);
            Logger.error(err);
            throw err;
        }
        this._atrHex = hexEncode(this._atr);
        this._isBusy = false;
        Logger.debug(`Card ATR: [${hexEncode(atr)}]`);
        Logger.debug(`Card protocol: ${protocol}`);
    }

    get protocol(): number {
        return this._protocol;
    }

    get atr(): Uint8Array {
        return this._atr;
    }

    get atrHex(): string {
        return this._atrHex;
    }

    get decodedAtr(): IAtrInfo | null {
        return this._decodedAtr;
    }

    isBusy(): boolean {
        return this._isBusy;
    }

    toString() {
        return `Card(atr:0x${this.atrHex})`;
    }

    /** Function that transforms each command before sending;
     * Can be used to add secure session authentication
     */
    setCommandTransformer(func?: (cmd: CommandApdu) => CommandApdu): this {
        if (typeof func === 'function') {
            Logger.trace('Setting card command transformer');
        } else {
            Logger.trace('Removing card command transformer');
        }
        this._commandTransformer = func;
        return this;
    }

    /** Function that transforms each command before sending;
     * Can be used to add secure session authentication
     */
    get commandTransformer(): undefined | ((cmd: CommandApdu) => CommandApdu) {
        return this._commandTransformer;
    }

    private _doCommandTransform(cmd: CommandApdu): CommandApdu {
        if (typeof this._commandTransformer === 'undefined') {
            return cmd;
        } else {
            Logger.trace('Applying command transformer');
            return this._commandTransformer(cmd);
        }
    }

    /** Function that transforms each response before returning it;
     * Can be used to add secure session authentication
     */
    setResponseTransformer(func?: (rsp: ResponseApdu) => ResponseApdu): this {
        if (typeof func === 'function') {
            Logger.trace('Setting card response transformer');
        } else {
            Logger.trace('Removing card response transformer');
        }
        this._responseTransformer = func;
        return this;
    }

    /** Function that transforms each response before returning it;
     * Can be used to add secure session authentication
     */
    get responseTransformer():
        | undefined
        | ((rsp: ResponseApdu) => ResponseApdu) {
        return this._responseTransformer;
    }

    private _doResponseTransform(rsp: ResponseApdu): ResponseApdu {
        if (typeof this._responseTransformer === 'undefined') {
            return rsp;
        } else {
            Logger.trace('Applying response transformer');
            return this._responseTransformer(rsp);
        }
    }

    /**
     * If set to true(default), `GET_RESPONSE` APDU gets sent automatically upon receiving `0x61XX` response.
     * Also the command `Le` value gets corrected and commands is sent again upon receiving `0x6CXX` response.
     */
    setAutoGetResponse(val: boolean = true): this {
        Logger.trace(`Setting autoGetResponse to "${val}"`);
        this._autoGetResponse = val;
        return this;
    }

    /**
     * If set to true(default), `GET_RESPONSE` APDU gets sent automatically upon receiving `0x61XX` response.
     * Also the command `Le` value gets corrected and commands is sent again upon receiving `0x6CXX` response.
     */
    set autoGetResponse(val: boolean) {
        this.setAutoGetResponse(val);
    }

    /** Current state of the autoGetResponse feature */
    get autoGetResponse(): boolean {
        return this._autoGetResponse;
    }

    private _issueCmdInternal(
        cmd: CommandApdu,
        callback: (err: any, response: ResponseApdu) => void,
    ): void {
        this._isBusy = true;
        let doCommandTransform: boolean = true;
        const respAcc = new ResponseApdu(); // response accumulator
        let middleCallback: (err: any, response: Uint8Array) => void;
        if (!this.autoGetResponse) {
            middleCallback = (err: any, respBuffer: Uint8Array) => {
                if (err) {
                    this._isBusy = false;
                    callback(err, new ResponseApdu());
                    return;
                }
                if (respBuffer.byteLength < 2) {
                    this._isBusy = false;
                    callback(
                        new Error(`Error response: [${hexEncode(respBuffer)}]`),
                        new ResponseApdu(),
                    );
                    return;
                }
                let response: ResponseApdu;
                try {
                    response = new ResponseApdu(respBuffer);
                } catch (error) {
                    this._isBusy = false;
                    callback(
                        new Error(`Error response: [${hexEncode(respBuffer)}]`),
                        new ResponseApdu(),
                    );
                    return;
                }
                this._eventEmitter.emit('response-received', {
                    device: this._device,
                    card: this,
                    command: cmd,
                    response,
                });
                try {
                    response = this._doResponseTransform(response);
                } catch (error: any) {
                    this._isBusy = false;
                    callback(
                        new Error(
                            `Error transformng response: ${error.message}`,
                        ),
                        new ResponseApdu(),
                    );
                    return;
                }
                this._isBusy = false;
                callback(err, response);
            };
        } else {
            middleCallback = (err: any, respBuffer: Uint8Array) => {
                if (err) {
                    this._isBusy = false;
                    callback(err, new ResponseApdu());
                    return;
                }
                if (respBuffer.byteLength < 2) {
                    this._isBusy = false;
                    callback(
                        new Error(`Error response: [${hexEncode(respBuffer)}]`),
                        new ResponseApdu(),
                    );
                    return;
                }
                let response: ResponseApdu;
                try {
                    response = new ResponseApdu(respBuffer);
                } catch (error) {
                    this._isBusy = false;
                    callback(
                        new Error(`Error response: [${hexEncode(respBuffer)}]`),
                        new ResponseApdu(),
                    );
                    return;
                }
                this._eventEmitter.emit('response-received', {
                    device: this._device,
                    card: this,
                    command: cmd,
                    response,
                });
                try {
                    response = this._doResponseTransform(response);
                } catch (error: any) {
                    this._isBusy = false;
                    callback(
                        new Error(
                            `Error transformng response: ${error.message}`,
                        ),
                        new ResponseApdu(),
                    );
                    return;
                }

                const bytesToGet = response.availableResponseBytes;
                if (bytesToGet > 0) {
                    if (response.dataLength > 0) respAcc.addData(response.data);
                    let cmdToResend: CommandApdu | undefined;
                    switch (true) {
                        case response.hasMoreBytesAvailable:
                            Logger.trace('Getting response automatically...');
                            cmdToResend = isoGetResponse(
                                response.availableResponseBytes,
                            );
                            doCommandTransform = false;
                            break;
                        case response.isWrongLe:
                            Logger.trace('Fixing command Le value...');
                            cmdToResend = new CommandApdu(cmd).setLe(
                                response.availableResponseBytes,
                            );
                            break;
                        default:
                            break;
                    }

                    if (typeof cmdToResend === 'undefined') {
                        this._isBusy = false;
                        callback(
                            err,
                            respAcc
                                .addData(response.data)
                                .setStatus(response.status),
                        );
                    } else {
                        if (doCommandTransform) {
                            try {
                                cmdToResend =
                                    this._doCommandTransform(cmdToResend);
                            } catch (error: any) {
                                this._isBusy = false;
                                callback(
                                    new Error(
                                        `Error transformng command: ${error.message}`,
                                    ),
                                    new ResponseApdu(),
                                );
                                return;
                            }
                        } else {
                            doCommandTransform = true;
                        }
                        this._eventEmitter.emit('command-issued', {
                            device: this._device,
                            card: this,
                            command: cmdToResend,
                        });
                        try {
                            this._device.transmit(
                                cmdToResend.toByteArray(),
                                maxTrResLen,
                                this._protocol,
                                middleCallback,
                            );
                        } catch (error: any) {
                            this._isBusy = false;
                            callback(
                                new Error(
                                    `Command transmission error: ${error.message}`,
                                ),
                                new ResponseApdu(),
                            );
                            return;
                        }
                    }
                } else {
                    this._isBusy = false;
                    callback(
                        err,
                        respAcc
                            .addData(response.data)
                            .setStatus(response.status),
                    );
                }
            };
        }

        let tCmd = cmd;
        if (doCommandTransform) {
            try {
                tCmd = this._doCommandTransform(cmd);
            } catch (error: any) {
                this._isBusy = false;
                callback(
                    new Error(`Error transformng command: ${error.message}`),
                    new ResponseApdu(),
                );
                return;
            }
            doCommandTransform = true;
        }

        this._eventEmitter.emit('command-issued', {
            device: this._device,
            card: this,
            command: tCmd,
        });

        try {
            this._device.transmit(
                tCmd.toByteArray(),
                maxTrResLen,
                this._protocol,
                middleCallback,
            );
        } catch (error: any) {
            this._isBusy = false;
            callback(
                new Error(`Command transmission error: ${error.message}`),
                new ResponseApdu(),
            );
            return;
        }
    }

    issueCommand(
        command: TBinData | CommandApdu,
        callback: (err: any, response: ResponseApdu) => void,
    ): void;
    issueCommand(command: TBinData | CommandApdu): Promise<ResponseApdu>;
    issueCommand(
        command: TBinData | CommandApdu,
        callback?: (err: any, response: ResponseApdu) => void,
    ): void | Promise<ResponseApdu> {
        Logger.trace('Issuing command to card');
        let cmd: CommandApdu;
        if (command instanceof CommandApdu) {
            cmd = command;
        } else {
            try {
                cmd = new CommandApdu(command);
            } catch (error: any) {
                throw new Error(`Command APDU error: ${error.message}`);
            }
        }

        let checkingErr: Error | undefined;

        if (cmd.byteLength < 4) {
            checkingErr = new Error(
                `Command too short; Min: 5 bytes; Received: ${cmd.byteLength} bytes; cmd: [${cmd.toString()}]`,
            );
        } else if (cmd.byteLength === 6) {
            if (cmd.getLc() === 0) {
                checkingErr = new Error(
                    `If Lc = 0, it should be omitted; cmd: [${cmd.toString()}]`,
                );
            }
            checkingErr = new Error(
                `Lc or Data missing; cmd: [${cmd.toString()}]`,
            );
        } else if (cmd.data.byteLength > CommandApdu.MAX_DATA_BYTE_LENGTH) {
            checkingErr = new Error(
                `Command data too long; Max: ${CommandApdu.MAX_DATA_BYTE_LENGTH} bytes; Received: ${cmd.data.byteLength} bytes; cmd: [${cmd.toString()}]`,
            );
        } else if (cmd.getLc() !== cmd.getData().byteLength) {
            checkingErr = new Error(
                `Lc and actual data length discrepancy; Lc:${cmd.getLc()} actual: ${cmd.getData().byteLength}; cmd: [${cmd.toString()}]`,
            );
        }

        if (callback) {
            if (checkingErr) {
                callback(checkingErr, new ResponseApdu([]));
                return;
            }
            try {
                this._issueCmdInternal(cmd, callback);
            } catch (error: any) {
                callback(
                    new Error(
                        `Error sending command to card: ${error.message}`,
                    ),
                    ResponseApdu.from([]),
                );
                return;
            }
            return;
        } else {
            return new Promise((resolve, reject) => {
                if (checkingErr) {
                    return reject(checkingErr);
                }
                const callback = (err: any, resp: ResponseApdu) => {
                    if (err) {
                        return reject(err);
                    } else {
                        return resolve(resp);
                    }
                };
                try {
                    this._issueCmdInternal(cmd, callback);
                } catch (error: any) {
                    return reject(
                        new Error(
                            `Error sending command to card: ${error.message}`,
                        ),
                    );
                }
            });
        }
    }

    on(
        eventName: 'command-issued',
        eventHandler: (event: {
            device: IDevice;
            card: Card;
            command: CommandApdu;
        }) => void,
    ): Card;
    on(
        eventName: 'response-received',
        eventHandler: (event: {
            device: IDevice;
            card: Card;
            command: CommandApdu;
            response: ResponseApdu;
        }) => void,
    ): Card;
    on(eventName: TCardEventName, eventHandler: (event: any) => void): Card {
        this._eventEmitter.on(eventName, eventHandler);
        return this;
    }

    once(
        eventName: 'command-issued',
        eventHandler: (event: {
            device: IDevice;
            card: Card;
            command: CommandApdu;
        }) => void,
    ): Card;
    once(
        eventName: 'response-received',
        eventHandler: (event: {
            device: IDevice;
            card: Card;
            command: CommandApdu;
            response: ResponseApdu;
        }) => void,
    ): Card;
    once(eventName: TCardEventName, eventHandler: (event: any) => void): Card {
        this._eventEmitter.once(eventName, eventHandler);
        return this;
    }

    removeListener(
        eventName: TCardEventName,
        eventHandler: (...args: any[]) => void,
    ): void {
        this._eventEmitter.removeListener(eventName, eventHandler);
    }

    off(
        eventName: TCardEventName,
        eventHandler: (...args: any[]) => void,
    ): void {
        this.removeListener(eventName, eventHandler);
    }

    removeAllListeners(eventName: TCardEventName): void {
        this._eventEmitter.removeAllListeners(eventName);
    }
}

export default Card;
