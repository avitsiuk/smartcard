import { CardReader } from './typesPcsclite';
import { TBinData } from './utils';
import CommandApdu from './commandApdu';
import ResponseApdu from './responseApdu';

export type TCardEventName = 'command-issued' | 'response-received';

export interface ICard {
    atr: Uint8Array;

    toString: () => string;

    /** Submits CommandAPDU and resolves upon completion */
    issueCommand(commandApdu: TBinData | CommandApdu): Promise<ResponseApdu>;
    /** Submits CommandAPDU and calls provided callback upon completion */
    issueCommand(
        commandApdu: TBinData | CommandApdu,
        callback: (err: any, response: ResponseApdu) => void,
    ): void;
    issueCommand(
        commandApdu: TBinData | CommandApdu,
        callback?: (err: any, response: ResponseApdu) => void,
    ): void | Promise<ResponseApdu>;

    /** Emitted upon submitting command to card. Event's command apdu is the actual command submitted to the card, after transformer has been applied (if any) */
    on(
        eventName: 'command-issued',
        eventHandler: (event: {
            device: IDevice;
            card: ICard;
            command: CommandApdu;
        }) => void,
    ): ICard;
    /** Emitted upon receiving response from card. Event's response apdu is the actual response received from the card, before transformation (if any) */
    on(
        eventName: 'response-received',
        eventHandler: (event: {
            device: IDevice;
            card: ICard;
            command: CommandApdu;
            response: ResponseApdu;
        }) => void,
    ): ICard;

    /** Emitted upon submitting command to card. Event's command apdu is the actual command submitted to the card, after transformer has been applied (if any) */
    once(
        eventName: 'command-issued',
        eventHandler: (event: {
            device: IDevice;
            card: ICard;
            command: CommandApdu;
        }) => void,
    ): ICard;
    /** Emitted upon receiving response from card. Event's response apdu is the actual response received from the card, before transformation (if any) */
    once(
        eventName: 'response-received',
        eventHandler: (event: {
            device: IDevice;
            card: ICard;
            command: CommandApdu;
            response: ResponseApdu;
        }) => void,
    ): ICard;

    removeListener(
        eventName: TCardEventName,
        eventHandler: (...args: any[]) => void,
    ): void;
    off(
        eventName: TCardEventName,
        eventHandler: (...args: any[]) => void,
    ): void;
    removeAllListeners(eventName: TCardEventName): void;
}

export type TDeviceEventName = 'error' | 'card-inserted' | 'card-removed';

export interface IDevice {
    reader: CardReader;
    name: string;
    card: ICard | null;

    transmit: (
        data: Uint8Array,
        res_len: number,
        protocol: number,
        cb: (err: any, response: Uint8Array) => void,
    ) => void;
    getName: () => string;
    toString: () => string;
    on(
        eventName: 'error',
        eventHandler: (event: { error: any; device: IDevice }) => void,
    ): IDevice;
    on(
        eventName: 'card-inserted',
        eventHandler: (event: { device: IDevice; card: ICard }) => void,
    ): IDevice;
    on(
        eventName: 'card-removed',
        eventHandler: (event: { device: IDevice; card: ICard }) => void,
    ): IDevice;
    once(
        eventName: 'error',
        eventHandler: (event: { error: any; device: IDevice }) => void,
    ): IDevice;
    once(
        eventName: 'card-inserted',
        eventHandler: (event: { device: IDevice; card: ICard }) => void,
    ): IDevice;
    once(
        eventName: 'card-removed',
        eventHandler: (event: { device: IDevice; card: ICard }) => void,
    ): IDevice;

    removeListener(
        eventName: TDeviceEventName,
        eventHandler: (...args: any[]) => void,
    ): void;
    off(
        eventName: TDeviceEventName,
        eventHandler: (...args: any[]) => void,
    ): void;
    removeAllListeners(eventName: TDeviceEventName): void;
}

export type TDevicesManagerEventName =
    | 'device-activated'
    | 'device-deactivated'
    | 'error';

export interface IDevicesManager {
    devices: { [key: string]: IDevice };

    onActivated: () => Promise<{
        device: IDevice;
        devManager: IDevicesManager;
    }>;
    onDeactivated: () => Promise<{
        device: IDevice;
        devManager: IDevicesManager;
    }>;
    lookup: (name: string) => IDevice | null;

    on(
        eventName: 'device-activated',
        eventHandler: (event: {
            device: IDevice;
            devManager: IDevicesManager;
        }) => void,
    ): IDevicesManager;
    on(
        eventName: 'device-deactivated',
        eventHandler: (event: {
            device: IDevice;
            devManager: IDevicesManager;
        }) => void,
    ): IDevicesManager;
    on(
        eventName: 'error',
        eventHandler: (event: {
            error: any;
            devManager: IDevicesManager;
        }) => void,
    ): IDevicesManager;
    once(
        eventName: 'device-activated',
        eventHandler: (event: {
            device: IDevice;
            devManager: IDevicesManager;
        }) => void,
    ): IDevicesManager;
    once(
        eventName: 'device-deactivated',
        eventHandler: (event: {
            device: IDevice;
            devManager: IDevicesManager;
        }) => void,
    ): IDevicesManager;
    once(
        eventName: 'error',
        eventHandler: (event: {
            error: any;
            devManager: IDevicesManager;
        }) => void,
    ): IDevicesManager;

    removeListener(
        eventName: TDevicesManagerEventName,
        eventHandler: (...args: any[]) => void,
    ): void;
    off(
        eventName: TDevicesManagerEventName,
        eventHandler: (...args: any[]) => void,
    ): void;
    removeAllListeners(eventName: TDevicesManagerEventName): void;
}
