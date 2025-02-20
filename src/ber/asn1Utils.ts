import { importBinData, type TBinData } from '../utils';

export function decodeOID(binData: TBinData): number[] {
    let inData: Uint8Array;
    try {
        inData = importBinData(binData);
    } catch (error: any) {
        throw new Error(`Error decoding OID: ${error.message}`);
    }

    if (inData.byteLength <= 0) return [];

    if ((inData[inData.byteLength - 1] & 0x08) !== 0) {
        throw new Error(`Error decoding OID: wrong data format`);
    }

    const subIdList: number[] = [];

    let offset = 0;
    while (offset < inData.byteLength) {
        let subIdLen = 0;
        for (let byteIdx = offset; byteIdx < inData.byteLength; byteIdx++) {
            if ((inData[byteIdx] & 0x80) === 0) {
                subIdLen = byteIdx + 1 - offset;
                break;
            }
        }
        const subIdSubarray = inData.subarray(offset, offset + subIdLen);
        const subId: Uint32Array = new Uint32Array([0]);
        for (let i = subIdSubarray.byteLength; i >= 0; i--) {
            subId[0] =
                subId[0] |
                ((subIdSubarray[i] & 0x7f) <<
                    (7 * (subIdSubarray.byteLength - 1 - i)));
        }
        if (offset === 0) {
            subIdList.push(Math.floor(subId[0] / 40));
            subIdList.push(subId[0] % 40);
        } else {
            subIdList.push(subId[0]);
        }
        offset += subIdLen;
    }
    return subIdList;
}
