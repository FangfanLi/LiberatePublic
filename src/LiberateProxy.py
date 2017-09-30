from netfilterqueue import NetfilterQueue
from scapy.all import *
from python_lib import *
import threading

# This LiberateProxy is the proxy class
# The definition of the parameters:
# Prot:     The protocol of the connection
# ChangeCode: The type of the changes that to be made on the connection:
#   IPi1:   Insert packet with low TTL
#   IPi2:   Insert packet with invalid version
#   IPi3:   Insert packet with invalid header length
#   IPi4:   Insert packet with Total length longer than payload
#   IPi5:   Insert packet with Total length shorter than payload
#   IPi6:   Insert packet with wrong protocol
#   IPi7:   Insert packet with wrong IP checksum
#   IPi8:   Insert packet with invalid options
#   IPi9:   Insert packet with deprecated options
#   TCPi1:  Insert packet with wrong sequence number
#   TCPi2:  Insert packet with wrong TCP checksum
#   TCPi3:  Insert packet with ACK flag not set
#   TCPi4:  Insert packet with invalid data offset
#   TCPi5:  Insert packet with invalid flag combination
#   UDPi1:  Insert packet with wrong UDP checksum
#   UDPi2:  Insert packet with length longer than payload
#   UDPi3:  Insert packet with length shorter than payload
#   IPs:    Split packet into fragments
#   TCPs:   Split packet into segments
#   Should have UDPs as well
#   UDPs:   Split one UDP packet into several
#   IPr:    Fragmented packet, out-of-order
#   TCPr:   Segmented packet, out-of-order
#   UDPr:   UDP packets out-of-order
#   IPfa:   Pause transmission for n seconds after sending the matching packets
#   IPfb:   Pause transmission for n seconds before sending the matching packets
#   TCPfa:  TTL-limited RST packet after sending the matching packets
#   TCPfb:  TTL-limited RST packet before sending the matching packets
# ModiSize: The size of the packet that will be Inserted in the connection
# ModiNum:
#   1. The number of inserted packet if insert injection
#   2. The number of fragments/segments to split into if splitting or reordering
# ProbTTL: The TTL that can reach the middlebox but not the destination
# PauseT: The time to wait for flushing techniques

class LiberateProxy(object):
    def __init__(self, Keywords, ChangeCode, Prot, ModiSize = 1, ModiNum = 1, ProbTTL = 1, PauseT = 10):
        self.Keywords = Keywords
        self.ChangeCode = ChangeCode
        self.Prot = Prot
        self.ModiSize = ModiSize
        self.ModiNum = ModiNum
        self.ProbTTL = ProbTTL
        self.PauseT = PauseT
        self.UDPr = True
        self.UDPswap = False
        self.MatchingPackets = []
        self.SendingPackets = []
        self.Spec = ChangeCode + '\t' + str(ModiSize) + '\t' + str(ModiNum) + '\t' + str(ProbTTL) + str(PauseT)

    def GetSpec(self):
        return self.Spec

    # This function would modify the certain field to make the packet inert
    def MakeInert(self, packet):
        if self.ChangeCode == 'IPi1' or self.ChangeCode == 'TTLP':
            packet[IP].ttl = self.ProbTTL
        elif self.ChangeCode == 'IPi2':
            packet[IP].version = 5
        elif self.ChangeCode == 'IPi3':
            packet[IP].ihl = 16
            del packet[IP].chksum
            del packet[IP].len
            del packet[TCP].chksum
            return packet
        elif self.ChangeCode == 'IPi4':
            # Set an IP length 80 bytes longer
            packet[IP].len += 80
            del packet[IP].chksum
            del packet[TCP].chksum
            return packet
        elif self.ChangeCode == 'IPi5':
            # Set the IP length to be the shortest
            packet[IP].len = 40
            del packet[IP].chksum
            del packet[TCP].chksum
            return packet
        elif self.ChangeCode == 'IPi6':
            srcIP = packet[IP].src
            dstIP = packet[IP].dst
            # Create a UDP packet for TCP traffic
            if self.Prot == 'tcp':
                dstport = packet[TCP].dport
                srcport = packet[TCP].sport
                rawpayload = packet[TCP].payload
                packet = IP(src=srcIP,dst=dstIP)/UDP(sport=srcport,dport=dstport)/rawpayload
            # Create a TCP packet for UDP traffic
            else:
                dstport = packet[TCP].dport
                srcport = packet[TCP].sport
                rawpayload = packet[TCP].payload
                packet = IP(src=srcIP,dst=dstIP)/TCP(sport=srcport,dport=dstport)/rawpayload
        elif self.ChangeCode == 'IPi7':
            packet[IP].chksum += 88
            del packet[IP].len
            del packet[TCP].chksum
            return packet
        elif self.ChangeCode == 'IPi8':
            packet[IP].options = [IPOption('%s%s'%('\xa0\x28','a'*38))]
        elif self.ChangeCode == 'IPi9':
            packet[IP].options = [IPOption('%s%s'%('\x88\x04','a'*2))]
        elif self.ChangeCode == 'TCPi1':
            # Decrease seq number, make it invalid
            packet[TCP].seq -= 12345
        elif self.ChangeCode == 'TCPi2':
            packet[TCP].chksum += 88
            del packet[IP].len
            del packet[IP].chksum
            return packet
        elif self.ChangeCode == 'TCPi3':
            packet[TCP].flags = 'P'
        elif self.ChangeCode == 'TCPi4':
            packet[TCP].dataofs = 16
        elif self.ChangeCode == 'TCPi5':
            packet[TCP].flags = 'SF'
        elif self.ChangeCode == 'UDPi1':
            packet[UDP].chksum += 88
        elif self.ChangeCode == 'UDPi2':
            packet[UDP].len += 80
            del packet[IP].len
            del packet[IP].chksum
            del packet[UDP].chksum
            return packet
        elif self.ChangeCode == 'UDPi3':
            packet[UDP].len = 8
            del packet[IP].len
            del packet[IP].chksum
            del packet[UDP].chksum
            return packet
        else:
            print '\n\t Wrong inert injection specified, no change made'
            return None
        # These are to ensure the correctness of these fields
        packet = self.RemoveFields(packet, 'IP')
        if self.Prot == 'tcp':
            if self.ChangeCode == 'IPi6':
                del packet[UDP].chksum
            else:
                del packet[TCP].chksum
        else:
            if self.ChangeCode == 'IPi6':
                del packet[TCP].chksum
            else:
                del packet[UDP].chksum

        return packet

    # Split the packet into ModiNum segments (TCP level)
    # Takes input the original packet and how many segments to split into
    # Output the list of segments broken into
    def SplitSegments(self, packet):
        data = str(packet[TCP].payload)
        header = packet.copy()
        header[TCP].remove_payload()
        remain = data
        sendPkts = []
        # Size is then the size of content in each packet
        size = len(data)/self.ModiNum
        baseseq = packet[TCP].seq
        # Put the first index - 1 segments into the list
        for x in xrange(self.ModiNum-1):
            part = remain[ :size]
            remain = remain[size: ]
            p = header.copy()
            p[TCP].seq = baseseq
            sp = p/part
            sp = self.RemoveFields(sp,'tcp')
            sendPkts.append(sp)
            baseseq += len(part)
        # Adding the last part of the data
        p = sendPkts[-1].copy()
        # Now remain should have the rest of the payload
        p[TCP].payload = remain
        p[TCP].seq += size
        p = self.RemoveFields(p,'tcp')
        sendPkts.append(p)
        return sendPkts

    # This function returns the packet with specified header fields removed from the input packet
    # For example, it clears the IP header/packet length and IP checksum
    # This is because Scapy will take care of correcting those fields if left clear
    def RemoveFields(self, packet, level):
        del packet[IP].ihl
        del packet[IP].len
        del packet[IP].chksum
        if level == 'IP':
            return packet
        elif level == 'tcp':
            del packet[TCP].chksum
        else:
            del packet[UDP].chksum
        return packet

    # Break packet into ModiNum smaller UDP packets
    def UDPBreak(self, packet):
        data = str(packet[UDP].payload)
        header = packet.copy()
        header[UDP].remove_payload()
        remain = data
        sendPkts = []
        # Size is then the size of content in each packet
        size = len(data)/self.ModiNum
        # Put the first index - 1 segments into the list
        for x in xrange(self.ModiNum):
            part = remain[ :size]
            remain = remain[size: ]
            p = header.copy()
            sp = p/part
            sp = self.RemoveFields(sp,'udp')
            sendPkts.append(sp)
        return sendPkts


    # This function break the packet into fragments/segments
    # Put the segmented/fragmented packets into self.SendingPackets
    def BreakPayload(self):
        if self.ChangeCode == 'IPs':
            for sPkt in self.MatchingPackets:
                # ModiNum is the number of fragments
                size = int(sPkt[IP].len/self.ModiNum)
                frags = fragment(sPkt,size)
                # Adding all fragments into the list
                self.SendingPackets += frags
        elif self.ChangeCode == 'TCPs':
            # In this case. ModiNum is the number of segments
            for sPkt in self.MatchingPackets:
                segments = self.SplitSegments(sPkt)
                self.SendingPackets += segments
        elif self.ChangeCode == 'IPr':
            for sPkt in self.MatchingPackets:
                # ModiNum is the number of fragments
                size = int(sPkt[IP].len/self.ModiNum)
                frags = fragment(sPkt,size)
                frags.reverse()
                # Adding all the reversed ordered fragments into the list
                self.SendingPackets += frags
        elif self.ChangeCode == 'TCPr':
            # In this case. ModiNum is the number of segments
            for sPkt in self.MatchingPackets:
                segments = self.SplitSegments(sPkt)
                segments.reverse()
                self.SendingPackets += segments
        # split these UDP packets
        elif self.ChangeCode == 'UDPs':
            for sPkt in self.MatchingPackets:
                udpsegments = self.UDPBreak(sPkt)
                self.SendingPackets += udpsegments
        elif self.ChangeCode == 'UDPr':
            # We need more than one packet to reverse the order here
            # Thus we return the list to indicate we saw the first UDP packet
            self.SendingPackets = self.MatchingPackets.reverse()
        else:
            print '\n\t Wrong splitting specified, no change made'
            self.SendingPackets = self.MatchingPackets



    # Inject a list of inert packets before the matching packets
    # Each of the same size : self.ModiSize
    # self.SendingPackets will contain the list of ordered packets to be sent out
    def InertInjection(self):
        # Make a copy of the first packet
        header = self.MatchingPackets[0].copy()
        if self.Prot == 'tcp':
            # Record its sequence
            seq_now = header[TCP].seq
            # Keey only the header
            header[TCP].remove_payload()
        else:
            header[UDP].remove_payload()
        # Create the inert packet(s)
        headers = []
        for i in xrange(self.ModiNum):
            headers.append(header.copy())
        # Three steps to make them 'legic' packets
        # 1.Replace the payload with random string with length specified in self.ModiSize
        # 2.Change the TCP sequence if the protocol is TCP
        rstring =  ''.join(random.choice(string.ascii_letters + string.digits) for x in range(self.ModiSize))
        InertPackets = []
        for header in headers:
            if self.Prot == 'tcp':
                header[TCP].seq = seq_now
                injectPkt = header/rstring
                seq_now += self.ModiSize
                # MakeInert will change the corresponding header as well as correct related fields (e.g. chksum)
                pktInert = self.MakeInert(injectPkt)
                # If changes are made to the inert packet
                if pktInert != None:
                    InertPackets.append(pktInert)
            else:
                injectPkt = header/rstring
                pktInert = self.MakeInert(injectPkt)
                # If changes are made to the inert packet
                if pktInert != None:
                    InertPackets.append(pktInert)
        # Concatenate the InertPackets list and Matching Packets together
        # self.SendingPackets are the ones we will send out
        self.SendingPackets = InertPackets + self.MatchingPackets

    # Create a TTL-limited RST packet with the same other attribute as sPkt
    def MakeRST(self, sPkt):
        RSTpkt = sPkt.copy()
        RSTpkt[TCP].remove_payload()
        # rstring =  ''.join(random.choice(string.ascii_letters + string.digits) for x in range(self.ModiSize))
        # RSTpkt = RSTpkt/rstring
        RSTpkt[IP].ttl = self.ProbTTL
        RSTpkt[TCP].flags = 'RA'
        # Inject a RST packet
        RSTpkt = self.RemoveFields(RSTpkt,'tcp')
        return RSTpkt

    def MakeRandom(self, sPackets):
        randomPackets = []
        for sPkt in sPackets:
            RandomsPkt = sPkt.copy()
            if self.Prot == 'tcp':
                # print '\r\n in TTLP', len(sPkt[TCP].payload), sPkt[TCP].payload
                rstring =  ''.join(random.choice(string.ascii_letters + string.digits) for x in range(len(sPkt[TCP].payload)))
                # print '\r\n in TTLP Rstring', len(rstring), rstring
                RandomsPkt[TCP].remove_payload()
            else:
                # print '\r\n in TTLP', len(sPkt[UDP].payload), sPkt[UDP].payload
                rstring =  ''.join(random.choice(string.ascii_letters + string.digits) for x in range(len(sPkt[UDP].payload)))
                # print '\r\n in TTLP Rstring', len(rstring), rstring
                RandomsPkt[UDP].remove_payload()
            rsPkt = RandomsPkt/rstring
            RandomPkt = self.RemoveFields(rsPkt, self.Prot)
            randomPackets.append(RandomPkt)

        return randomPackets

    # Send a list of Scapy packets in order
    def sendAll(self, Packets):
        for spacket in Packets:
            # print '\r\n IN SENDING ALL!!', spacket.show2()
            send(spacket, verbose=False)

    # Main part of LiberateProxy:
    # Now every packet needed is in self.MatchingPackets
    # Evade Using method specified in self.ChangeCode
    def EvasionModify(self):
        # Special case if we are probing TTL, we need to make sure the
        # Matching packets are TTL-limited while packets with random payload can arrive
        # Reduce the matching packets' TTL
        if self.ChangeCode == 'TTLP':
            for Spkt in self.MatchingPackets:
                InertSpkt = Spkt.copy()
                self.SendingPackets.append(self.MakeInert(InertSpkt))
                randomPackets = self.MakeRandom(self.MatchingPackets)
            # Appending len(self.MatchingPackets) with seeded random payload
            self.SendingPackets += randomPackets
        # Inert Injection, self.SendingPackets has all packets need to be sent
        elif 'i' in self.ChangeCode:
            self.InertInjection()
        # Flushing before
        elif 'f' in self.ChangeCode:
            # This is when flushing after sending matching packets,
            if 'a' in self.ChangeCode:
                # send matching packets first
                self.sendAll(self.MatchingPackets)
                # TCP flushing
                if 'TCP' in self.ChangeCode:
                    RSTpkt = self.MakeRST(self.MatchingPackets[-1])
                    send(RSTpkt, verbose = False)
                # Else, IP flushing, pause
                else:
                    time.sleep(self.PauseT)
                return
            # else if flushing before sending matching packets
            elif 'b' in self.ChangeCode:
                if 'TCP' in self.ChangeCode:
                    RSTpkt = self.MakeRST(self.MatchingPackets[0])
                    send(RSTpkt, verbose = False)
                else:
                    time.sleep(self.PauseT)
                # Send matching packets out after flushing
                self.sendAll(self.MatchingPackets)
                return
        # Spliting/Reordering
        elif ('s' in self.ChangeCode) or ('r' in self.ChangeCode):
            # self.SendingPackets has all packets need to be sent
            self.BreakPayload()
        # Send all packets in self.SendingPackets out
        print '\r\n IN EVASION MODIFY, About to send all SendingPackets'
        self.sendAll(self.SendingPackets)


    # Check whether the keywords are in the payload
    # The keywords must appear in the same sequence
    # For example, if keywords are ['I', 'have', 'best']
    # CheckKeywords returns TRUE for 'I only have best food'
    # But False for 'This is the best food I have'
    def CheckKeywords(self, payload, numSeen):
        # print '\r\n IN CHECK KEYWORDS',numSeen, payload
        kMatch = True
        sp = 0
        for key in self.Keywords[numSeen]:
            keyp = payload.find(key, sp)
            sp = keyp
            if sp == -1:
                kMatch = False
        return kMatch

    def AllMatchingPacket(self, latestPkt):
        # numSeen is the number of packets we already seen and stored
        # We need the a sequence n packets each with specific payload
        # self.MatchingPackets stores the first k that are already matched
        # Need to check whether latestPkt contains all keywords specified in Keywords[numSeen]
        # If it fails to match, send everything out and accept latestPkt cause it is not the series of packets needed, and return False
        # Elif it matches append it into self.MatchingPackets, and check whether it is the last one we needed
        #       If yes, return True, and do EvasionModify
        #       Else, return False

        # We need to extract the payload from latestPkt
        # sPkt is latestPkt transformed into Scapy object
        # print '\n\t ENTERED ALLMATCHING'
        sPkt = IP(latestPkt.get_payload())
        # rawp is the raw payload after the transport layer header
        if self.Prot == 'tcp':
            rawp = sPkt[TCP].payload
        else:
            rawp = sPkt[UDP].payload

        numSeen = len(self.MatchingPackets)
        # If we have all the matching packets already, and already did modification
        if numSeen == len(self.Keywords):
            latestPkt.accept()
            # Reset the matching packets, and keep watching
            self.MatchingPackets = []
        # If this latest packet fails the matching content checking
        elif not self.CheckKeywords(str(rawp), numSeen):
            # Send the previous stored packets out
            # Via scapy method send()
            if len(self.MatchingPackets) > 0 :
                self.sendAll(self.MatchingPackets)
            # Reset the matching packets, and keep watching
            self.MatchingPackets = []
            latestPkt.accept()
            return False
        else:
            # This packet belongs to the matching packet
            # Tell netfilter queue to drop it, it will be sent out via Scapy send()
            latestPkt.drop()
            self.MatchingPackets.append(sPkt)
            # Everything is ready!
            print '\r\n Found Matching Packet,',len(self.MatchingPackets),len(self.Keywords)
            if len(self.MatchingPackets) == len(self.Keywords):
                return True
            else:
                return False

    def check_and_evade(self, pkt):
        # First check whether pkt is the last packet that we are waiting
        if self.AllMatchingPacket(pkt):
            self.EvasionModify()

    def run(self):
        print '\n\t Liberate Proxy running '
        self.nfqueue = NetfilterQueue()
        # Bind the nfqueue on the nfqueue 1
        # For each packet in the queue, check whether there are keywords, if yes, make change accordingly, if no, pass it through
        self.nfqueue.bind(1, self.check_and_evade)
        self.queueT = threading.Thread(target=self.nfqueue.run)
        self.queueT.daemon = True
        self.queueT.start()
        # print '\n\t Should be running as a daemon'

    def persistRun(self):
        # print '\n\t I am running '
        self.nfqueue = NetfilterQueue()
        # 2.Bind the nfqueue on the nfqueue 1
        # For each packet in the queue, check whether there are keywords, if yes, make change accordingly, if no, pass it through
        self.nfqueue.bind(1, self.check_and_evade)
        self.nfqueue.run()
        # print '\n\t Should be running as a daemon'

    def stop(self):
        print('\n\t Stopping liberate Proxy')
        self.nfqueue.unbind()
        print('\n\t Stopped' )