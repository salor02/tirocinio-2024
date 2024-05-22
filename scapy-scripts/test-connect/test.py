from scapy.layers.bluetooth import *
import scapy.layers.bluetooth as bt
import select
import os
import time

os.system('hciconfig hci0 down')

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
    
client = BluetoothUserSocket(0)

test_num = 50

for i in range(test_num):
    print(f"Startint test {i}")
    handle = None
    res = client.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection(paddr='40:4c:ca:4b:51:e2'))
    while True:
        incoming_pkt = recv_packet(client,1)
        if not incoming_pkt:
            break
        # Check if event code is 'LE Meta Event', p1190
        if hasattr(incoming_pkt, 'code') and incoming_pkt.code == 0x3e:
            # Check if subevent code is 'LE Connection Complete Event', p1190
            if hasattr(incoming_pkt, 'event') and incoming_pkt.event == 0x01:
                print("LE Connection Complete Event")
                handle = incoming_pkt.handle
                print(f'Client handle found: {handle}')
    time.sleep(5)
    if not handle:
        print("Connection failed")
        continue
    else:
        res = client.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Disconnect(handle=handle))
        print("Disconnected")
    time.sleep(5)




