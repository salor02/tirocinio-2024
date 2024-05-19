from time import sleep
from scapy.fields import (
    ByteField,
    ShortField,
    SignedByteField,
    StrFixedLenField
)
from scapy.layers.bluetooth import EIR_Hdr, EIR_Manufacturer_Specific_Data, UUIDField, LowEnergyBeaconHelper, IntField, BluetoothHCISocket
from scapy.packet import Packet

bt = BluetoothHCISocket(0)

RADIUS_NETWORKS_MFG = 0x0118

class MyBacon(Packet, LowEnergyBeaconHelper):
    name = "MyBacon"
    beacon_code = b"\x0A\x0a"
    fields_desc = [
        StrFixedLenField("header", beacon_code, len(beacon_code)),

        # The spec says this is 20 bytes, with >=16 bytes being an
        # organisational unit-specific identifier. However, the Android library
        # treats this as UUID + uint16 + uint16.
        ShortField("id1", None),
        IntField("ciao", None),
        SignedByteField("tx_power", None)
    ]

    @classmethod
    def magic_check(cls, payload):
        """
        Checks if the given payload is for us (starts with our magic string).
        """
        return payload.startswith(cls.magic)

    def build_eir(self):
        """Builds a list of EIR messages to wrap this frame."""

        # Note: Company ID is not required by spec, but most tools only look
        # for manufacturer-specific data with Radius Networks' manufacturer ID.
        return LowEnergyBeaconHelper.base_eir + [
            EIR_Hdr() / EIR_Manufacturer_Specific_Data(
                company_id=RADIUS_NETWORKS_MFG) / self
        ]

EIR_Manufacturer_Specific_Data.register_magic_payload(MyBacon)

cycle = 0

while True:
    sleep(1)
    cycle = cycle + 1
    ab = MyBacon(
        id1=324,
        ciao=cycle,
        tx_power=-50,
    )
    bt.sr(ab.build_set_advertising_data())
    print("SENT: " + str(cycle))

pkt = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=0)
ans, unans = bt.sr(pkt)
pkt = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Advertise_Enable(enable=1)
ans, unans = bt.sr(pkt)