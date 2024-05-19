from scapy.layers.bluetooth import *
import scapy.layers.bluetooth as bt
from time import sleep
import select
import os

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
    
server = BluetoothUserSocket(1)
client = BluetoothUserSocket(0)

#ans, unans = bt.sr(pkt)
pkt_client = [
    HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Reset(),
    HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=0),
    HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=1),
    HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertising_Data(data='\x02\x01\x06\x03\x03\x0d\x18\x0f\x09\x45\x53\x50\x5f\x47\x41\x54\x54\x53\x5f\x44\x45\x4d\x4f')
    #HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertising_Data(data='\x02\x01\x06\x03\x02\x12\x18\x0e\x09\x45\x4c\x4b\x2d\x42\x4c\x45\x44\x4f\x4d\x20\x20\x20'),
    #HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertising_Data(data='\x02\x01\x02\x06\x09\x50\x69\x78\x6f\x6f'),
    ]

pkt_server = [
    HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection(paddr='40:4c:ca:4b:51:e2'),
    #HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection(paddr='be:59:f9:01:25:37'),
    #HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection(paddr='11:75:58:2b:3c:9d'),
]  

for x in pkt_server:
    res = server.send(x)

for x in pkt_client:
    res = client.send(x)

while True:
    incoming_pkt = recv_packet(server,3)
    if not incoming_pkt:
        break
    if hasattr(incoming_pkt, 'handle'):
        server_handle = incoming_pkt.handle
        print(f'Server handle found: {server_handle}')

current_waiting = client
print('Starting capture from client...')

while True:
    incoming_pkt = recv_packet(current_waiting,600)
    
    if not incoming_pkt:
        print(f'Final queue from server: {queue(server)}')
        print(f'Final queue from client: {queue(client)}')
        break
    # Check if event code is 'LE Meta Event', p1190
    if hasattr(incoming_pkt, 'code') and incoming_pkt.code == 0x3e:
        # Check if subevent code is 'LE Connection Complete Event', p1190
        if hasattr(incoming_pkt, 'event') and incoming_pkt.event == 0x01:
            print("LE Connection Complete Event")
            client_handle = incoming_pkt.handle
            print(f'Client handle found: {client_handle}')
            #to_send = HCI_Hdr()/HCI_ACL_Hdr(handle=client_handle)/param_update
            #client.send(to_send)

    if hasattr(incoming_pkt, 'type') and incoming_pkt.type == 0x02 and bt.ATT_Hdr:
        if current_waiting == client and incoming_pkt.opcode in request_opcode:
            print(f'Forwarding [client -> server]: {incoming_pkt[HCI_ACL_Hdr]}')
            to_send = HCI_Hdr()/HCI_ACL_Hdr(handle=server_handle)/incoming_pkt[L2CAP_Hdr]
            server.send(to_send)
            current_waiting = server
            print('Switching, now waiting for server response')

        if current_waiting == server and incoming_pkt.opcode in response_opcode:
            incoming_pkt.show()
            print(f'Forwarding [server -> client]: {incoming_pkt[HCI_ACL_Hdr]}')
            to_send = HCI_Hdr()/HCI_ACL_Hdr(handle=client_handle)/incoming_pkt[L2CAP_Hdr]
            client.send(to_send)
            current_waiting = client
            print('Switching, now waiting for client response')

        if current_waiting == client and incoming_pkt.opcode == 0x52:
            print(f'Forwarding [client -> server]: {incoming_pkt[HCI_ACL_Hdr]}')
            incoming_pkt.show()
            #print(f'Writing data: {incoming_pkt.value}')
            to_send = HCI_Hdr()/HCI_ACL_Hdr(handle=server_handle)/incoming_pkt[L2CAP_Hdr]
            server.send(to_send)


#pkt = HCI_Hdr()/HCI_ACL_Hdr()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Request(gatt_handle=0)
#pkt = HCI_Hdr()/HCI_ACL_Hdr(handle=4)/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x002a, data='\xff')


#bt.sniff(store=False, prn = lambda x: print(x), lfilter = lambda p: HCI_ACL_Hdr in p)
#pkt.show()


