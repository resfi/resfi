from scapy.all import *
import time


aps = {}
def packet_handler(pkt) :
    # if packet has 802.11 layer, and type of packet is Data frame
    if pkt.haslayer(Dot11) and pkt.type == 2:
            DS = pkt.FCfield & 0x3
            to_DS = DS & 0x1 != 0
            from_DS = DS & 0x2 != 0
            length = len(pkt)
            if to_DS and not from_DS:
                if str(pkt.addr3) == "ff:ff:ff:ff:ff:ff":
                    return
                #Address 1 = BSSID
                #Address 2 = Source
                #Address 3 = Destination
                bssid = pkt.addr1
                sta = pkt.addr2
                sender = pkt.addr3
                ap = bssid
                #print "STA->AP: \tBSSID: "+str(bssid)+" Sender: "+str(sender)+" STA: "+str(sta)+ " length: "+str(length) +" sent: "+str(aps[ap][sta][sent])
                if ap in aps:
                    if sta in aps[ap]:
                        print ""
                        #okay we have that STA already
                    else:
                        aps[ap][sta]={}
                        aps[ap][sta]['active'] = False 
                        aps[ap][sta]['ts'] = int(round(time.time() * 1000))
                        aps[ap][sta]['sent'] = {}    
                        aps[ap][sta]['rec'] = {}
                        aps[ap][sta]['sent']=0
                        aps[ap][sta]['rec']= 0
                else:
                    aps[ap] = {}
                    aps[ap]['activeStas']= []
                    aps[ap][sta]={}
                    aps[ap][sta]['active'] = False
                    aps[ap][sta]['ts'] = int(round(time.time() * 1000))
                    aps[ap][sta]['sent'] = {}
                    aps[ap][sta]['rec'] = {}
                    aps[ap][sta]['sent'] = 0
                    aps[ap][sta]['rec']= 0
                aps[ap][sta]['sent'] = aps[ap][sta]['sent'] + int(length)
                print "STA->AP: \tBSSID: "+str(bssid)+" STA: "+str(sta)+ " length: "+str(length) +"\t#sum sent: "+str(aps[ap][sta]['sent'])

            elif from_DS and not to_DS:
                if str(pkt.addr1) == "ff:ff:ff:ff:ff:ff":
                    return
                #Multicast filtering...
                #If the least significant bit of the first octet of an address is set to 0 (zero), the frame is meant to reach only one receiving NIC
                firstOctRec = str(pkt.addr1)[:2]
                scale = 16 ## equals to hexadecimal
                num_of_bits = 8
                firstOctRecBin = bin(int(firstOctRec, scale))[2:].zfill(num_of_bits)
                notUnicast = firstOctRecBin[7:]
                if notUnicast == '1':
                    return
                #Address 1 = Destination
                #Address 2 = BSSID
                #Address 3 = Source
                bssid = pkt.addr2
                sta = pkt.addr1
                receiver = pkt.addr3
                ap = bssid
                if ap in aps:
                    if sta in aps[ap]:
                        print ""
                        #okay we have that STA already
                    else:
                        aps[ap][sta]={}
                        aps[ap][sta]['active'] = False
                        aps[ap][sta]['ts'] = int(round(time.time() * 1000))
                        aps[ap][sta]['sent'] = {}    
                        aps[ap][sta]['rec'] = {}
                        aps[ap][sta]['sent']=0
                        aps[ap][sta]['rec']= 0
                else:
                    aps[ap] = {}
                    aps[ap]['activeStas']= []
                    aps[ap][sta]={}
                    aps[ap][sta]['active'] = False
                    aps[ap][sta]['ts'] = int(round(time.time() * 1000))
                    aps[ap][sta]['sent'] = {} 
                    aps[ap][sta]['rec'] = {}
                    aps[ap][sta]['sent'] = 0
                    aps[ap][sta]['rec']= 0
                aps[ap][sta]['rec'] = aps[ap][sta]['rec'] + int(length)

                print "AP->STA: \tBSSID: "+str(bssid)+" STA: "+str(sta) + " length: "+str(length) +"\t#sum rec: "+str(aps[ap][sta]['rec'])
         #
         #Ch
            #eck if a STA is active
            cts= int(round(time.time() * 1000))
            for ap in aps:
                for sta in aps[ap]:
                     if sta != "activeStas":
                         if (cts - aps[ap][sta]['ts']) > 20000:
                             if aps[ap][sta]['sent'] > 50000 or aps[ap][sta]['rec'] > 50000:
                                 aps[ap][sta]['active'] = True
                                 if sta not in aps[ap]['activeStas']:
                                     aps[ap]['activeStas'].append(sta)
                             else: 
                                 aps[ap][sta]['active'] = False
                                 if sta in aps[ap]['activeStas']:
                                     index = aps[ap]['activeStas'].index(sta)
                                     del aps[ap]['activeStas'][index]

                             aps[ap][sta]['sent'] = 0
                             aps[ap][sta]['rec'] = 0
                             aps[ap][sta]['ts'] = cts
            print "#######"
            for ap in aps:
                print "Active STAs AP[ "+str(ap)+"]: "+str(aps[ap]['activeStas'])
             

sniff(iface="mon0", prn=packet_handler)
