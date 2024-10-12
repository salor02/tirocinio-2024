from scapy.layers.bluetooth import *
import scapy.layers.bluetooth as bt
import select
import os
import time

os.system('hciconfig hci0 down')

def recv_packet(socket, timeout):
    packet_check = select.select([socket], [], [], timeout)

    if packet_check[0]:
        return socket.recv()
    else:
        return False
    
client = BluetoothUserSocket(0)

test_num = 100

successful_conn = 0

for i in range(test_num):
    print(f"Starting test {i}")
    handle = None
    res = client.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection(paddr='40:4c:ca:4b:51:e2'))
    while True:
        incoming_pkt = recv_packet(client,1)
        if not incoming_pkt:
            break
        if HCI_LE_Meta_Connection_Complete in incoming_pkt:
            print(f"Connection {i} completed")
            handle = incoming_pkt.handle
            print(f'Client handle found: {handle}')
            successful_conn += 1
    time.sleep(5)
    if not handle:
        print("Connection failed")
        continue
    else:
        res = client.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Disconnect(handle=handle))
        print("Disconnected")
    time.sleep(5)

print(f'Test completed, {successful_conn} successful connections')





