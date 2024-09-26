from time import sleep
from scapy.layers.bluetooth import *
import random

#apertura socket
bt = BluetoothHCISocket(0)

#lunghezza del dato costiuito dal tipo + dato effettivo
LENGTH = b'\x05'

#AD_type
MANUFACTURER_SPECIFIC_DATA_AD_TYPE = b'\xff'

#company ID richiesto da standard, in questo caso corrisponde a Samsung
COMPANY_ID = b'\xfc\x91'

#hearthbeat iniziale
hearthbeat = 80

#avvio modalità di advertising
pkt = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=1)
ans, unans = bt.sr(pkt)
print('Advertising phase started')

while hearthbeat > 60:
    increment = random.randint(-3, 3)

    #l'hearthbeat ha un valore su 2 byte
    hearthbeat = hex(hearthbeat + increment)[2:].zfill(4)

    #costruzione AD_data come da standard
    AD_data = LENGTH + MANUFACTURER_SPECIFIC_DATA_AD_TYPE + COMPANY_ID + bytes.fromhex(hearthbeat)
    
    #costruzione ed invio comando
    command = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertising_Data(data=AD_data)
    bt.sr(command)

    hearthbeat = int(hearthbeat, base=16)
    print("Sent command:")
    print(f'\tCurrent hearthbeat: {hearthbeat}')
    print(f'\tAD data: {command[HCI_Cmd_LE_Set_Advertising_Data].data}')
    sleep(1)
    
#disattivazione modalità di advertising
pkt = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=0)
ans, unans = bt.sr(pkt)
print('Advertising phase stopped')
