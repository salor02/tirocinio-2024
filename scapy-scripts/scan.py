from scapy.layers.bluetooth import *
import scapy.layers.bluetooth as bt
import select
import os
from time import sleep

os.system('hciconfig hci0 down; hciconfig hci1 down')

sock = BluetoothUserSocket(1)

def recv_packet(socket, timeout):
    packet_check = select.select([socket], [], [], timeout)

    if packet_check[0]:
        return socket.recv()
    else:
        return False
    

pkts = [
    HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Scan_Parameters(type=0),
    HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Scan_Enable(enable=1, filter_dups=1)
    ]


for x in pkts:
    res = sock.send(x)

sleep(1)

res = sock.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Scan_Enable(enable=0))

devices = dict()

while True:
    incoming_pkt = recv_packet(sock,0)
    if not incoming_pkt:
        break
    if HCI_LE_Meta_Advertising_Reports in incoming_pkt:
        adv_report = incoming_pkt[HCI_LE_Meta_Advertising_Reports]
        for report in adv_report.reports:
            #report.show()
            devices[report.addr] = report.data

for idx, dev in enumerate(devices.items()):
    device_name = ""

    for data in dev[1]:
        if EIR_CompleteLocalName in data:
            device_name = data.local_name.decode()
            break

    print(f'[{idx}] {dev[0]} {device_name}')

selected_device_idx = input("Select device to emulate: ")
devices_list = list(devices.items())
selected_device = devices_list[int(selected_device_idx)]

pkts = [
    HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Reset(),
    HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=0),
    HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=1),
    HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertising_Data(data=selected_device[1])
    ]

for x in pkts:
    res = sock.send(x)

sleep(100)