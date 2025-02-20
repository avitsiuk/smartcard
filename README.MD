# SmartCardX

## About

This package expands upon original [`smartcard` library](https://github.com/tomkp/smartcard) by [tomkp](https://github.com/tomkp) and is built around [`pcsclite` library](https://github.com/santigimeno/node-pcsclite) by [Santiago Gimeno](https://github.com/santigimeno)  
[Original `smartcard` package](https://www.npmjs.com/package/smartcard) on NPM  
[`pcsclite` package](https://www.npmjs.com/package/pcsclite) on NPM

> Tested with `ACR39U` and `ACR122U` readers

## Main features overview

- CommonJS + ES6 modules support
- Event-based devices and cards management (like in the original `smartcard` package)
- CommandAPDU class with helper methods for simpler command construction. (no more bitwise)
- ResponseAPDU with helpers for status decoding according to Iso7816 specifications.
- Auto GetResponse in case of `0x61XX` response. (can be disabled)
- Auto command adjustment in case of `0x6CXX` response. (can be disabled).
- Built-in Iso7816 commands(still expanding)
- Built-in GlobalPlatform commands (still expanding)
- Built-in GlobalPlatform secure sessions
  - SCP02 (i=55)
  - SCP11b
- Built-in BER encoder/decoder with wildcard search (e.g. `/6f/*/88`)
- Card ATR decode

## TODO list

- API Documentation
- Add missing Iso7816 commands
- Add missing GlobalPlatform commands
- Add EMV BER tags dictionary for EMV/Iso7816/GlobalPlatform tags
- SCP03 support
- SCP11a with mutual authentication support
- BER object in-place editing. Currently a new object must be created.

## Dependencies (Debian/Ubuntu)

### PCSC system drivers

Install basic dependencies by running  
`sudo apt install build-essential libpcsclite1 libpcsclite-dev pcscd`  
and check pcscd service status for any error with  
`service pcscd status`

Optionally install pcsc tools package  
`sudo apt install pcsc-tools`  
and check if your reader(s) and card(s) are working by executing  
`pcsc_scan`  
This should show all (contact and NFC) readers recognized by your system and print info about inserted cards (if any).

## Issues (Debian/Ubuntu)

### Busy NFC issues

Sometimes NFC readers won't work because of other drivers blocking the usb bus.
Plug in your reader and check pcscd service logs:

```text
$ journalctl -u pcscd.service
...
xxx XX XX:XX:XX xxxxxx pcscd[5465]: 29870365 ccid_usb.c:672:OpenUSBByName() Can't claim interface 1/10: LIBUSB_ERROR_BUSY
...
```

`LIBUSB_ERROR_BUSY` tells that the interface is used by something else.

Check what driver is using the device:

```text
$ lsusb -t
/:  Bus 01.Port 1: Dev 1, Class=root_hub, Driver=xhci_hcd/16p, 480M
    |__ Port 1: Dev 23, If 0, Class=Chip/SmartCard, Driver=pn533, 12M
```

Then view the dependency tree of that driver (`pn533` in this case)

```text
$ lsmod | grep pn533
Module                  Size  Used by
pn533_usb              20480  0
pn533                  49152  1 pn533_usb
nfc                   147456  1 pn533
```

in this case we have following dependency tree

```text
pn533_usb
  └pn533
    └nfc
```

There are two possible ways to disable those drivers:  

1. Unload modules from kernel:  
`sudo rmmod pn533_usb pn533 nfc`  
In case you need to reenable them again just run:  
`sudo modprobe pn533_usb pn533 nfc`  
    > No system reboot required

2. Add drivers to blacklist  
Open(create) file `/etc/modprobe.d/nfc-blacklist.conf` and add following lines:

    ```text
    blacklist pn533_usb
    blacklist pn533
    blacklist nfc
    ```

    >System reboot required

Now install `libnfc`:  
`sudo apt install libnfc-bin`

And finally restart `pcscd`:  
`sudo service pcscd restart`

Use one of the following tools to check if the reader is working:

```text
$ nfc-scan-device
nfc-scan-device uses libnfc 1.8.0
1 NFC device(s) found:

- ACS / ACR122U PICC Interface:
    acr122_usb:001:023
```

```text
$ nfc-list
nfc-list uses libnfc 1.8.0
NFC device: ACS / ACR122U PICC Interface opened
```

```text
$ pcsc_scan
Using reader plug'n play mechanism
Scanning present readers...
0: ACS ACR122U PICC Interface 00 00

Fri Aug 23 16:47:33 2024
 Reader 0: ACS ACR122U PICC Interface 00 00
  Event number: 0
  Card state: Card removed,
```

### Deprecated OpenSSL crypto functions

Secure Channel Protocol 02 uses cryptographic functions which are no longer supported on NodeJS v17+  
Example:  
`Error: error:0308010C:digital envelope routines::unsupported`  

In order to reenable those functions you need to add `--openssl-legacy-provider` to environment variable `NODE_OPTIONS` (create if missing)
For example:  
`export NODE_OPTIONS=--openssl-legacy-provider`  
or  
`export NODE_OPTIONS="$NODE_OPTIONS --openssl-legacy-provider"`  
Multiple options must be separated by a space

## API

> // Under construction

## Example demo.ts

This code cam be found in package repository

```ts
import {
    Logger,
    PcscDevicesManager,
    Device,
    Card,
    CommandApdu,
    Utils,
    BER,
    Iso7816Commands,
    GPCommands,
    GPUtils,
    ResponseApdu,
} from 'smartcardx';

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

        // logging card communications
        // event.card.on('command-issued', (event) => {
        //     console.log(`[${device.name}][CMD]<< [${event.command}]`)
        // })
        // event.card.on('response-received', (event) => {
        //     console.log(`[${device.name}][RSP]>> [${Utils.hexEncode([...event.response.data])}][${Utils.hexEncode([...event.response.status])}](${event.response.meaning})`)
        // })

        console.log(Utils.decodeAtr(card.atr));

        console.log('Selecting default applet...');
        console.log();

        // Uncomment this to disable autoGetResponse feature
        // In that case GET_RESPONSE commands must be sent manually
        // event.card.autoGetResponse = false;

        event.card.issueCommand(Iso7816Commands.select())
            .then((selectResponse) => {
                console.log();

                let berObj: BER.BerObject | undefined;
                try {
                    berObj = BER.BerObject.parse(selectResponse.data);
                } catch (error) {
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
                return GPUtils.getInfo(card);
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
```
