from scapy.layers.bluetooth import *
import scapy.layers.bluetooth as bt
from scapy.all import wrpcap, rdpcap
import select
import os
from utility import *
from binascii import hexlify

class MITM:
    def __init__(self, client_sock, server_sock, server_handle, server_paddr):
        self.server_sock = server_sock
        self.server_handle = server_handle
        self.server_paddr = server_paddr

        self.client_sock = client_sock
        self.client_handle = None
        self.client_paddr = None

        self.currently_waiting = None

        self.client_sent_pkts = []

    def capture_client(self, timeout):
        incoming_pkt = recv_packet(self.client_sock, timeout)
        while incoming_pkt:
            if HCI_LE_Meta_Connection_Complete in incoming_pkt:
                self.client_handle = incoming_pkt.handle
                self.client_paddr = incoming_pkt.paddr
                self.currently_waiting = self.client_sock
                return True
            incoming_pkt = recv_packet(self.client_sock, timeout)

        return False
    
    def switch_waiting(self):
        if self.currently_waiting == self.client_sock:
            self.currently_waiting = self.server_sock
            print('Switching, now waiting for server response')

        else:
            self.currently_waiting = self.client_sock
            print('Switching, now waiting for client request')

    def ATT_forward(self, recipient, pkt):
        if recipient == self.client_sock:
            to_send = HCI_Hdr()/HCI_ACL_Hdr(handle=self.client_handle)/pkt[L2CAP_Hdr]
            self.client_sock.send(to_send)
            self.client_sent_pkts.append(to_send)

        elif recipient == self.server_sock:
            to_send = HCI_Hdr()/HCI_ACL_Hdr(handle=self.server_handle)/pkt[L2CAP_Hdr]
            self.server_sock.send(to_send)

        else:
            raise Exception("[ERROR] Can't forward this packet")
        
        if not ATT_Write_Command in pkt:
            self.switch_waiting()


    def run(self, timeout):
        while True:
            incoming_pkt = recv_packet(self.currently_waiting, timeout)
            #incoming_pkt.show()
            if not incoming_pkt:
                print(f"No packet has been received from client in the last {timeout} seconds, disconnecting")
                break
            
            if self.currently_waiting == self.client_sock:
                if is_ATT_Request(incoming_pkt):
                    print(f'ATT_Request [client -> server]: {incoming_pkt[HCI_ACL_Hdr]}')
                    decode(incoming_pkt)
                    self.ATT_forward(self.server_sock, incoming_pkt)
                elif ATT_Write_Command in incoming_pkt:
                    print(f'Write_Command [client -> server]: {incoming_pkt[HCI_ACL_Hdr]}')
                    decode(incoming_pkt)
                    self.ATT_forward(self.server_sock, incoming_pkt)

            else: 
                if is_ATT_Response(incoming_pkt) and self.currently_waiting == self.server_sock:
                    #incoming_pkt.show()
                    print(f'ATT_Response [server -> client]: {incoming_pkt[HCI_ACL_Hdr]}')
                    decode(incoming_pkt)
                    self.ATT_forward(self.client_sock, incoming_pkt)

            
        

    