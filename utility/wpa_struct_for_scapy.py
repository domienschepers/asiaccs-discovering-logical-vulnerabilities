#/usr/bin/python2.7
from scapy.all import *

# Sources: 
# https://github.com/bonfa/netsec/blob/master/src/packetStruct/wpa_struct_for_scapy.py
# https://fossies.org/dox/scapy-2.3.1/wpa__eapol_8py_source.html

def hex2str(string):
    """Convert a binary string to hex-decimal representation."""
    return ''.join('%02x' % c for c in map(ord, string))

class XStrFixedLenField(scapy.fields.StrFixedLenField):
    """String-Field with nice repr() for hexdecimal strings"""
    def i2repr(self, pkt, x):
        return hex2str(StrFixedLenField.i2m(self, pkt, x))

class XStrLenField(scapy.fields.StrLenField):
    """String-Field of variables size with nice repr() for hexdecimal strings"""
    def i2repr(self, pkt, x):
        return hex2str(StrLenField.i2m(self, pkt, x))

class EAPOL_Key(scapy.packet.Packet):
	"""EAPOL Key frame"""
	name = "EAPOL Key"
	fields_desc = [ scapy.fields.ByteEnumField("DescType", 254, {2: "RSN Key", 254: "WPA Key"}) ]
scapy.packet.bind_layers( scapy.layers.l2.EAPOL, EAPOL_Key, type=3 )

class EAPOL_AbstractEAPOLKey(scapy.packet.Packet):
    """Base-class for EAPOL WPA/RSN-Key frames"""
    fields_desc = [
        scapy.fields.FlagsField("KeyInfo", 0, 16,
                                ["HMAC_MD5_RC4", "HMAC_SHA1_AES", "undefined",\
                                 "pairwise", "idx1", "idx2", "install",\
                                 "ack", "mic", "secure", "error", "request", "encrypted"
                                ]),
        scapy.fields.ShortField("KeyLength", 0),
        scapy.fields.LongField("ReplayCounter", 0),
        XStrFixedLenField("Nonce", '\x00'*32, 32),
        XStrFixedLenField("KeyIV", '\x00'*16, 16),
        XStrFixedLenField("WPAKeyRSC", '\x00'*8, 8),
        XStrFixedLenField("WPAKeyID", '\x00'*8, 8),
        XStrFixedLenField("WPAKeyMIC", '\x00'*16, 16),
        scapy.fields.ShortField("WPAKeyLength", 0),
        scapy.fields.ConditionalField(
                        XStrLenField("WPAKey", None, length_from = lambda pkt: pkt.WPAKeyLength),\
                        lambda pkt: pkt.WPAKeyLength > 0 \
                        )
      ]

class EAPOL_WPAKey(EAPOL_AbstractEAPOLKey):
    name = "EAPOL WPA Key"
    keyscheme = 'HMAC_MD5_RC4'
scapy.packet.bind_layers( EAPOL_Key, EAPOL_WPAKey, DescType=254 )

class EAPOL_RSNKey(EAPOL_AbstractEAPOLKey):
    name = "EAPOL RSN Key"
    keyscheme = 'HMAC_SHA1_AES'
scapy.packet.bind_layers( EAPOL_Key, EAPOL_RSNKey, DescType=2   )
