from scapy.layers.bluetooth import *
import scapy.layers.bluetooth as bt
from scapy.all import wrpcap, rdpcap
import select
import os
from binascii import hexlify
from time import sleep

os.system('hciconfig hci0 down; hciconfig hci1 down')

#p 2201 della core specification 4.2
request_opcode = [0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12]
response_opcode = [0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f, 0x11, 0x13]

def recv_packet(socket, timeout):
    packet_check = select.select([socket], [], [], timeout)

    if packet_check[0]:
        return socket.recv()
    else:
        return False
    
def queue(socket):
    print("Counting final queue")
    count = 0
    packet_check = select.select([socket], [], [], 1)

    while packet_check[0]:
        pkt = socket.recv()
        print(pkt)
        count+=1
        packet_check = select.select([socket], [], [], 1)

    return count
    
server = BluetoothUserSocket(0)
client = BluetoothUserSocket(1)

pkt_server = [
    #HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection(paddr='40:4c:ca:4b:51:e2'),
    HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection(paddr='be:59:f9:01:25:37'),
    #HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection(paddr='11:75:58:2b:3c:9d'),
]  

for x in pkt_server:
    res = server.send(x)

while True:
    incoming_pkt = recv_packet(server,3)
    if not incoming_pkt:
        break
    if hasattr(incoming_pkt, 'handle'):
        server_handle = incoming_pkt.handle
        print(f'Server handle found: {server_handle}')


print('Starting interactive mode')
pkts_list = rdpcap('./sent_pkts_led.pcap')

pkts_list = pkts_list[200:220]
while True:
    for idx,pkt in enumerate(pkts_list):
        if ATT_Write_Request in pkt:
            data = pkt[ATT_Write_Request]
            print(f'[{idx}] Write Request\t--\tGatt Handle: {data.gatt_handle}\t|\tData: {hexlify(data.data)}')
            #pkt.show()
        if ATT_Write_Command in pkt:
            data = pkt[ATT_Write_Command]
            print(f'[{idx}] Write Command\t--\tGatt Handle: {data.gatt_handle}\t|\tData: {hexlify(data.data)}')
            #pkt.show()

    to_send_idx = int(input("Select packet to send: "))
    if to_send_idx == -1:
        break

    selected_pkt = pkts_list[to_send_idx]

    to_send = HCI_Hdr()/HCI_ACL_Hdr(handle=server_handle)/selected_pkt[L2CAP_Hdr]
    server.send(to_send)
    
    if not to_send.opcode == 0x52:
        print('Switching, now waiting for server response')
        incoming_pkt = recv_packet(server,10)
        if not incoming_pkt:
            print(f'Final queue from server: {queue(server)}')
            break




sleep(50)

