from scapy.all import *
import time
import zmq
import sys
import thread
import json

aps = {}
interval = 10000 #ms
threshold = 2000 # bytes

def zmqServer():
    port = "9999"
    if len(sys.argv) > 1:
            port =  sys.argv[1]
            int(port)


    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind("tcp://*:%s" % port)
    print "ZMQ Sniffer Server running!"
    while True:
            #  Wait for next request from clien
            #print "Waiting for request"
            message = socket.recv()
            #print "Received request: ", message
            data = json.dumps(aps)
            socket.send(str(data))




def packet_handler(pkt) :
    #print pkt.notdecoded.encode('hex')
    if pkt.haslayer(Dot11) and pkt.type == 2:
            DS = pkt.FCfield & 0x3
            to_DS = DS & 0x1 != 0
            from_DS = DS & 0x2 != 0
            length = len(pkt)
            freq = pkt.notdecoded[18:20]
            if len(freq) == 2 and isinstance(freq, basestring):
                freq = struct.unpack('h', freq)[0]
            else:
                freq = -1
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
                        #print ""
                        pass
                        #okay we have that STA already
                    else:
                        aps[ap][sta]={}
                        aps[ap]['freq'] = freq
                        aps[ap][sta]['active'] = False 
                        aps[ap][sta]['ts'] = int(round(time.time() * 1000))
                        aps[ap][sta]['sent'] = {}    
                        aps[ap][sta]['rec'] = {}
                        aps[ap][sta]['sent']=0
                        aps[ap][sta]['rec']= 0
                else:
                    aps[ap] = {}
                    aps[ap]['activeStas'] = []
                    aps[ap]['freq'] = freq
                    aps[ap][sta]={}
                    aps[ap][sta]['active'] = False
                    aps[ap][sta]['ts'] = int(round(time.time() * 1000))
                    aps[ap][sta]['sent'] = {}
                    aps[ap][sta]['rec'] = {}
                    aps[ap][sta]['sent'] = 0
                    aps[ap][sta]['rec']= 0
                aps[ap][sta]['sent'] = aps[ap][sta]['sent'] + int(length)
                aps[ap]['freq'] = freq
                aps[ap]['last_refresh'] = int(round(time.time() * 1000))
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
                        #print ""
                        pass
                        #okay we have that STA already
                    else:
                        aps[ap][sta]={}
                        aps[ap]['freq'] = freq
                        aps[ap][sta]['active'] = False
                        aps[ap][sta]['ts'] = int(round(time.time() * 1000))
                        aps[ap][sta]['sent'] = {}    
                        aps[ap][sta]['rec'] = {}
                        aps[ap][sta]['sent']=0
                        aps[ap][sta]['rec']= 0
                else:
                    aps[ap] = {}
                    aps[ap]['activeStas']= []
                    aps[ap]['freq'] = freq
                    aps[ap][sta]={}
                    aps[ap][sta]['active'] = False
                    aps[ap][sta]['ts'] = int(round(time.time() * 1000))
                    aps[ap][sta]['sent'] = {} 
                    aps[ap][sta]['rec'] = {}
                    aps[ap][sta]['sent'] = 0
                    aps[ap][sta]['rec']= 0
                aps[ap][sta]['rec'] = aps[ap][sta]['rec'] + int(length)
                aps[ap]['freq'] = freq
                aps[ap]['last_refresh'] = int(round(time.time() * 1000))

                print "AP->STA: \tBSSID: "+str(bssid)+" STA: "+str(sta) + " length: "+str(length) +"\t#sum rec: "+str(aps[ap][sta]['rec'])
         #
         #Ch
            #eck if a STA is active
            cts= int(round(time.time() * 1000))
            for ap in aps:
                for sta in aps[ap]:
                     if sta != "activeStas" and sta != "freq" and sta != "last_refresh":
                         if (cts - aps[ap][sta]['ts']) > interval:
                             if aps[ap][sta]['sent'] > threshold or aps[ap][sta]['rec'] > threshold:
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
    #print "#######"
    cts= int(round(time.time() * 1000))
    for ap in aps:
        if cts - aps[ap]['last_refresh'] > (4*interval):
            del aps[ap]
            print "Deleted AP: "+str(ap)
            return
        else:
            pass
            #print "Active STAs AP[ "+str(ap)+"]: "+str(aps[ap]['activeStas'])
             

thread.start_new_thread(zmqServer, ())
sniff(iface="mon0", prn=packet_handler)
