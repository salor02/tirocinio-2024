import asyncio

from construct import Array, Byte, Const, Int8sl, Int16ub, Int32sb, Struct
from construct.core import ConstError

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

mybacon_format = Struct(
    "type_length" / Const(b"\x0a\x0a"),
    "uuid" / Int16ub,
    "HR" / Int32sb
)

def device_found(device: BLEDevice, advertisement_data: AdvertisementData):
    print(advertisement_data.manufacturer_data[0x0118])

    try:
        beacon_data = advertisement_data.manufacturer_data[0x0118]
        mybacon = mybacon_format.parse(beacon_data)

        print(f"RAW:\t{beacon_data}")
        print(f"UUID:\t{mybacon.uuid}")
        print(f"HR:\t{mybacon.HR}")
        print(f"RSSI:\t{advertisement_data.rssi} dBm")
        print(47 * "-")

    except KeyError:
        pass
    except ConstError:
        pass


async def main():
    scanner = BleakScanner(detection_callback=device_found)
    
    while True:
        await scanner.start()
        await asyncio.sleep(1.0)
        await scanner.stop()


asyncio.run(main())