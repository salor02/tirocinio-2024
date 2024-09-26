import asyncio
from bleak import BleakScanner

#company ID richiesto da standard, in questo caso corrisponde a Samsung
COMPANY_ID = b'\xfc\x91'

def detection_callback(device, advertisement_data):

    manufacturer_data = advertisement_data.manufacturer_data
    
    for company_id, data in manufacturer_data.items():
        #se company id corrisponde a quello ricercato significa che il dato è di nostro interesse
        if company_id == int.from_bytes(COMPANY_ID, byteorder='little'):
            
            #i primi 2 byte corrispondono al battito, cioè le prime 4 cifre della converisone in esadecimale
            hearthbeat = data.hex()[0:4]
            hearthbeat_value = int(hearthbeat, 16)
            
            print("Advertising received:")
            print(f'\tCurrent hearthbeat: {hearthbeat_value}')
            print(f'\tAD data: {data.hex()}')
            print(50 * '-')

async def scan_for_beacons():
    scanner = BleakScanner(detection_callback=detection_callback)
    
    #avvio processo di scanning e chiusura automatica
    print("Starting scanning...")
    await scanner.start()
    await asyncio.sleep(30)
    await scanner.stop()
    print("Scanning process stopped")

if __name__ == "__main__":
    asyncio.run(scan_for_beacons())
