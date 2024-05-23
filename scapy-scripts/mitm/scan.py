from scapy.layers.bluetooth import *
import select
from os import system
from time import sleep
from utility import *

def start_scanning(socket):
    pkts = [
        #HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Reset(),
        #HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=0),
        #HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=1),
        #HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertising_Data(data='\x02\x01\x06\x03\x03\x0d\x18\x0f\x09\x45\x53\x50\x5f\x47\x41\x54\x54\x53\x5f\x44\x45\x4d\x4f'),
        HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Scan_Parameters(type=0),
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


def enable_emulation(socket, adv_data):
    pkts = [
        HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Reset(),
        HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=0),
        HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=1),
        HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertising_Data(data=adv_data)
    ]

    if not send_all(socket, pkts):
        raise Exception("[ERROR] Failed to initialize emulation")

def victim_server_connect(socket, victim_addr):
    pkts = [
        HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection(paddr=victim_addr)
    ]

    if not send_all(socket, pkts):
        raise Exception("[ERROR] Connection to the victim server failed")
    
    server_handle = None

    while True:
        incoming_pkt = recv_packet(socket,3)
        if not incoming_pkt:
            break
        if hasattr(incoming_pkt, 'handle'):
            server_handle = incoming_pkt.handle
    
    if not server_handle:
        raise Exception("[ERROR] Failed to retrieve server handle")
    return server_handle