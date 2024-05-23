import select
from scapy.layers.bluetooth import *
from binascii import hexlify

ATT_Request = [
    ATT_Exchange_MTU_Request,
    ATT_Find_Information_Request,
    ATT_Find_By_Type_Value_Request,
    ATT_Read_By_Type_Request,
    ATT_Read_Request,
    ATT_Read_Blob_Request,
    ATT_Read_Multiple_Request,
    ATT_Read_By_Group_Type_Request,
    ATT_Write_Request,
    ATT_Prepare_Write_Request,
    ATT_Execute_Write_Request]

ATT_Response = [
    ATT_Exchange_MTU_Response,
    ATT_Find_Information_Response,
    ATT_Find_By_Type_Value_Response,
    ATT_Read_By_Type_Response,
    ATT_Read_Response,
    ATT_Read_Blob_Response,
    ATT_Read_Multiple_Response,
    ATT_Read_By_Group_Type_Response,
    ATT_Write_Response,
    ATT_Prepare_Write_Response,
    ATT_Execute_Write_Response,
    ATT_Error_Response
]

ATT_Handle_Value = [
    ATT_Handle_Value_Notification,
    ATT_Handle_Value_Indication,
]


def recv_packet(socket, timeout):
    packet_check = select.select([socket], [], [], timeout)

    if packet_check[0]:
        return socket.recv()
    else:
        return False
    
def send_all(socket, pkts):
    for pkt in pkts:
        sent_bytes = socket.send(pkt)
    
    if sent_bytes == 0:
        return False
    else:
        return True
    
def is_ATT_Request(pkt):
    for type in ATT_Request:
        if type in pkt:
            return True
    return False

def is_ATT_Response(pkt):
    for type in ATT_Response:
        if type in pkt:
            return True
        
    if hasattr(pkt , 'type') and pkt.type == 0x02:
        if pkt.opcode == 0x13:
            return True
    
    return False

def decode(pkt):
    if ATT_Write_Command in pkt:
        print(f' - gatt_handle: {pkt.gatt_handle}')
        print(f' - value: {hexlify(pkt.data)}')
    elif ATT_Write_Request in pkt:
        print(f' - gatt_handle: {pkt.gatt_handle}')
        print(f' - data: {hexlify(pkt.data)}')
    elif ATT_Read_Request in pkt:
        print(f' - gatt_handle: {pkt.gatt_handle}')
    else:
        return False
    
    return True
