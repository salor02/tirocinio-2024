from scapy.layers.bluetooth import *
import select
from os import system
from time import sleep
from utility import *

def start_scanning(socket):
    pkts = [
        HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Scan_Parameters(type=0), #scansione passiva
        HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Scan_Enable(enable=1, filter_dups=1)
    ]

    if not send_all(socket, pkts):
        raise Exception("[ERROR] Failed to start the scanning process")
    
def stop_scanning(socket):
    pkts = [
        HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Scan_Enable(enable=0)
    ]

    if not send_all(socket, pkts):
        raise Exception("[ERROR] Failed to stop the scanning process")

def collect_scanning_result(socket):
    devices = dict()

    #costruisce una lista di dispositivi di cui è stato ricevuto almeno un pacchetto di advertising
    while True:
        incoming_pkt = recv_packet(socket,0)
        if not incoming_pkt:
            break
        if HCI_LE_Meta_Advertising_Reports in incoming_pkt:
            adv_report = incoming_pkt[HCI_LE_Meta_Advertising_Reports]
            for report in adv_report.reports:
                devices[report.addr] = report.data
    
    return devices

def show_scanning_result(devices):
    for idx, dev in enumerate(devices.items()):
        device_name = ""

        for type in dev[1]:
            if EIR_CompleteLocalName in type:
                device_name = type.local_name.decode()
                break

        print(f'[{idx}] {dev[0]} {device_name}')