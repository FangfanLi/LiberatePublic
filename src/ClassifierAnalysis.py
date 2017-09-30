import pickle, replay_client, urllib2, urllib
from python_lib import *
from collections import deque

'''
This is the main script for Classifiers Unclassified
1. Run original replay
2. Run random/bit inverted replay
3. If differentation detected, perform binary search to identify the matching rule
'''

Replaycounter = 0


class AnalyzerI(object):
    '''
    This class contains all the methods to interact with the analyzerServer
    '''
    def __init__(self, ip, port):
        self.path = ('http://'
                     + ip
                     + ':'
                     + str(port)
                     + '/Results')


    def ask4analysis(self, id, historyCount, testID):
        '''
        Send a POST request to tell analyzer server to analyze results for a (userID, historyCount)

        server will send back 'True' if it could successfully schedule the job. It will
        return 'False' otherwise.

        This is how and example request look like:
            method: POST
            url:    http://54.160.198.73:56565/Results
            data:   userID=KSiZr4RAqA&command=analyze&historyCount=9
        '''
        # testID specifies the test number in this series of tests
        # testID = 0 is the first replay in this series of tests, thus it is the baseline (original) to be compared with
        data = {'userID':id, 'command':'analyze', 'historyCount':historyCount, 'testID':testID}
        res = self.sendRequest('POST', data=data)
        return res

    def getSingleResult(self, id, historyCount, testID):
        '''
        Send a GET request to get result for a historyCount and testID

        This is how an example url looks like:
            method: GET
            http://54.160.198.73:56565/Results?userID=KSiZr4RAqA&command=singleResult&historyCount=9
        '''
        # testID specifies the test number in this series of tests
        data = {'userID':id, 'command':'singleResult', 'testID':testID}

        if isinstance(historyCount,int):
            data['historyCount'] = historyCount

        res = self.sendRequest('GET', data=data)
        return res

    def sendRequest(self, method, data=''):
        '''
        Sends a single request to analyzer server
        '''
        data = urllib.urlencode(data)

        if method.upper() == 'GET':
            req = urllib2.Request(self.path + '?' + data)

        elif method.upper() == 'POST':
            req  = urllib2.Request(self.path, data)

        res = urllib2.urlopen(req).read()
        print '\r\n RESULTS',res
        return json.loads(res)

def processResult(result):
    # Only if ks2ratio > ks2Beta (this is the confidence interval) the ks2 result is trusted, otherwise only the area test is used
    # Default suggestion: areaThreshold 0.1, ks2Beta 95%, ks2Threshold 0.05
    # KS2:
    # ks2Threshold is the threshold for p value in the KS2 test, if p greater than it, then we cannot
    # reject the hypothesis that the distributions of the two samples are the same
    # If ks2pvalue suggests rejection (i.e., p < ks2Threshold), where accept rate < (1 - ks2Beta), the two distributions are not the same (i.e., differentiation)
    # Else, the two distributions are the same, i.e., no differentiation
    # Area:
    # if area_test > areaThreshold, the two distributions are not the same (i.e., Differentiation)
    # Else, the two distributions are the same, i.e., no differentiation
    # Return result score, 0  : both suggests no differentiation
    #                      1  : inconclusive conclusion from two methods (Considered as no differentiation so far)
    #                      2  : both suggests differentiation
    #                      if target trace has less throughput, return negative value respectively, e.g., -1 means target trace is throttled
    #        result rate: differentiated rate = (normal - throttled)/throttled

    areaT = Configs().get('areaThreshold')
    ks2Beta  = Configs().get('ks2Beta')
    ks2T  = Configs().get('ks2Threshold')

    ks2Ratio = float(result['ks2_ratio_test'])
    ks2Result = float(result['ks2pVal'])
    areaResult = float(result['area_test'])

    # ks2_ratio test is problematic, sometimes does not give the correct result even in the obvious cases, not using it so far
    # 1.Area test passes and 2.With confidence level ks2Beta that the two distributions are the same
    # Then there is no differentiation
    if (areaResult < areaT) and (ks2Result > ks2T):
        outres = 0
    # 1.Area test does not pass and 2.With confidence level ks2Beta that the two distributions are not the same
    # Then there is differentiation
    elif (areaResult > areaT) and (ks2Result < ks2T):
        outres = 2
        # rate = (result['xput_avg_test'] - result['xput_avg_original'])/min(result['xput_avg_original'], result['xput_avg_test'])
    # Else inconclusive
    else:
        outres = 1
        PRINT_ACTION('##### INConclusive Result, area test is' + str(areaResult) + 'ks2 test is ' + str(ks2Result), 0)
        # rate = (result['xput_avg_test'] - result['xput_avg_original'])/min(result['xput_avg_original'], result['xput_avg_test'])

    return outres

def GetMeta(PcapDirectory, numPackets, client_ip):

    Meta = {'Client':[], 'Server':[]}
    changeMeta = {'Client':[], 'Server':[]}

    # The default pickleFile name
    picklesFile = 'test.pcap_server_all.pickle'
    picklecFile = 'test.pcap_client_all.pickle'

    for file in os.listdir(PcapDirectory):
        if file.endswith(".pcap_server_all.pickle"):
            picklesFile = file
        elif file.endswith(".pcap_client_all.pickle"):
            picklecFile = file

    serverQ, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName = \
        pickle.load(open(PcapDirectory + picklesFile,'r'))

    clientQ, udpClientPorts, tcpCSPs, replayName = \
        pickle.load(open(PcapDirectory + picklecFile, 'r'))

    # There should always be at least one client packet
    if len(clientQ) > 0:
        for cPacket in clientQ:
            Meta['Client'].append(len(cPacket.payload.decode('hex')))

    # There should only be one protocol that is in the pcap
    # Thus the one with an csp in it
    Prot = 'tcp'
    for P in serverQ.keys():
        if serverQ[P] != {}:
            Prot = P
    # There should only be a single csp as well
    csp = serverQ[Prot].keys()[0]

    if len(serverQ) > 0:
        # For UDP traffic
        if Prot == 'udp':
            for sPacket in serverQ[Prot][csp]:
                Meta['Server'].append(len(sPacket.payload.decode('hex')))

        else:
            for sPacket in serverQ[Prot][csp]:
                Meta['Server'].append(len(sPacket.response_list[0].payload.decode('hex')))

    # Now we need to filter out the packets that we are going to investigate
    packetMeta = os.path.abspath(PcapDirectory + '/' + 'packetMeta')
    with open(packetMeta, 'r') as f:
        # We need to check how many client packets and server packets are in the first numPackets packets
        count = 0
        clientc = 0
        serverc = 0
        for line in f:
            l = line.replace('\n', '').split('\t')
            srcIP     = l[5]
            if client_ip == srcIP:
                clientc += 1
            else:
                serverc +=1
            count += 1
            # We only need to make changes in the first numPackets packets
            if count == numPackets:
                break

    changeMeta['Client'] = Meta['Client'][:clientc]
    changeMeta['Server'] = Meta['Server'][:serverc]

    return changeMeta,csp,Prot, replayName, clientQ, serverQ

# This function would run replay client against the replay server for one time
# The tricky part is to get the classification result, the method now is to write into the 'Result.txt' file

def runReplay(PcapDirectory, pacmodify, analyzerI):

    global Replaycounter

    classification = None

    cmpacNum = -1
    caction = None
    cspec = None
    smpacNum = -1
    saction = None
    sspec = None

    Side, Num, Action, Mspec = pickle.loads(pacmodify)

    if Side == 'Client':
        cmpacNum = Num
        caction = Action
        cspec = Mspec
    elif Side == 'Server':
        smpacNum = Num
        saction = Action
        sspec = Mspec

    configs = Configs()

    # replay_client.run(configs = configs, pcapdir = PcapDirectory, cmpacNum = cmpacNum, caction = caction, cspec = cspec,
    #                       smpacNum = smpacNum, saction = saction, sspec = sspec)
    try:
        replayResult = replay_client.run(configs = configs, pcapdir = PcapDirectory, cmpacNum = cmpacNum, caction = caction, cspec = cspec,
                          smpacNum = smpacNum, saction = saction, sspec = sspec)
    except:
        print '\r\n Error when running replay'
        replayResult = None

    time.sleep(5)
    permaData = PermaData()
    try:
        PRINT_ACTION(str(analyzerI.ask4analysis(permaData.id, permaData.historyCount, configs.get('testID'))), 0 )
    except Exception as e:
        PRINT_ACTION('\n\n\n####### COULD NOT ASK FOR ANALYSIS!!!!! #######\n\n\n' + str(e),0)
    PRINT_ACTION(replayResult , 0 )

    # ASK the replay analyzer for KS2 result, i.e., analyzerResult
    # replayResult is whether the replay finished, used for testing censorship
    # Classify_result = (replayResult, analyzerResult)

    # Give 15s for the server to process the result and insert metrics into the database
    time.sleep(15)
    PRINT_ACTION('Fetching analysis result from the analyzer server',0)
    res = analyzerI.getSingleResult(permaData.id, permaData.historyCount, configs.get('testID'))

    # Check whether results are successfully fetched


    if res['success'] == True:
        # Process result here
        pres = processResult(res['response'])
        if pres == 1:
            PRINT_ACTION('INConclusive Result. Considered as NOT different from Original replay', 0)
            classification = 'Original'
        elif pres == 2:
            PRINT_ACTION('Different from Original replay', 0)
            classification = 'NotOriginal'
        else:
            PRINT_ACTION('NOT Different from Original replay', 0)
            classification = 'Original'
    else:
        # Only use whether the replayResult as classification
        PRINT_ACTION('\r\n Failed in fetching result ' + res['error'], 0)
        classification = replayResult

    # TODO Supplement YOUR OWN method to get the classification result here

    # OR Manually type what this traffic is classified as
    # classification = raw_input('Is it classified the same as original replay? "YES" or "NO"?')

    # In our testbed
    # Run miniterm_m.py, which would read the classification result from middlebox and write it into a file called out.txt
    # subprocess.call('sudo python miniterm_m.py --cr -b 19200 /dev/ttyS0', stdout=subprocess.PIPE , shell=True)
    # dport = 80
    # time.sleep(1)
    # keyword = ':' + str(dport)
    # try:
    #     if os.path.isfile('out.txt'):
    #         with open('out.txt', 'r') as f:
    #             for line in f.readlines():
    #                 if keyword in line:
    #                     classify_result = line.split(':')[0]
    #     subprocess.call('sudo rm out.txt', stdout=subprocess.PIPE , shell=True)
    # except:
    #     print '\n\t ********Exception when getting classification result!'
    #     classification = 'Wrong!'
    #
    # print '\r\n This replay is ',classify_result


    return classification

# This function looks into the regions in question one by one
# Each suspect region only has less than 4 bytes, filtered by the previous process
def detailAnalysis(PcapDirectory, Side, PacketNum, Length, original, analysisRegion, analyzerI):
    LeftB = analysisRegion[0][0]
    RightB = analysisRegion[0][1]
    Masked = analysisRegion[1]
    noEffect = []
    hasEffect = []
    for num in xrange(RightB - LeftB):
        newMask = list(Masked)
        newMask.append((LeftB+num,LeftB+num+1))
        pacmodify = pickle.dumps((Side, PacketNum, 'ReplaceI', newMask))
        Classi = Replay(PcapDirectory, pacmodify, analyzerI)
        if Classi == original:
            noEffect.append(LeftB+num)
        else:
            hasEffect.append(LeftB+num)

    return hasEffect


# RPanalysis stands for Random Payload analysis, which does the binary randomization to locate the matching contents
# It would return the key regions by randomizing different part of the payload
# The key regions are the regions that trigger the classification
def RPanalysis(PcapDirectory, Side, PacketNum, Length, original, analyzerI):
    allRegions = []
    # RAque is the queue that stores the analysis that are needed to run
    # each element of the queue is a pair of a. (pair of int) and b. (list of pairs): ((x,y),[(a,b),(c,d)])
    # (x,y) is the suspected region, meaning somewhere in this region triggers the classification
    # [(a,b),(c,d)] is the list of regions that we know does not have effect, so those region would be randomized
    # We would randomize half of the bytes in (x,y), and enqueue the new region based on the result of replaying both halves
    RAque = deque()
    # Initialization
    RAque.append(((0,Length),[]))
    analysis = RAque.popleft()
    # While the length of each suspected region is longer than 4, we need to keep doing the binary randomization
    while analysis[0][1] - analysis[0][0] > 4:
        LeftBar = analysis[0][0]
        RightBar = analysis[0][1]
        MidPoint = LeftBar + (RightBar - LeftBar)/2
        MaskedRegions = analysis[1]
        LeftMask = list(MaskedRegions)
        RightMask = list(MaskedRegions)
        LeftMask.append((LeftBar, MidPoint))
        RightMask.append((MidPoint, RightBar))

        # print '\n\t  PREPARING LEFT MASK',MaskedRegions,LeftMask
        lpacmodify = pickle.dumps((Side, PacketNum, 'ReplaceI', LeftMask))
        LeftClass = Replay(PcapDirectory, lpacmodify, analyzerI)
        # print '\n\t  PREPARING RIGHT MASK',MaskedRegions,RightMask
        rpacmodify = pickle.dumps((Side, PacketNum, 'ReplaceI', RightMask))
        RightClass = Replay(PcapDirectory, rpacmodify, analyzerI)
        # Four different cases
        if LeftClass == original and RightClass != original:
            RAque.append(((MidPoint, RightBar), LeftMask))

        elif LeftClass != original and RightClass == original:
            RAque.append(((LeftBar, MidPoint), RightMask))

        elif LeftClass != original and RightClass != original:
            RAque.append(((LeftBar,MidPoint), MaskedRegions))
            RAque.append(((MidPoint,RightBar), MaskedRegions))

        else:
            allRegions = ['Both sides are not differentiated when masked', LeftMask, RightMask]
            break

        analysis = RAque.popleft()

    if allRegions != []:
        return allRegions

    else:
        # Put the last poped element back
        RAque.appendleft(analysis)

        for region in RAque:
            effectRegion = detailAnalysis(PcapDirectory, Side, PacketNum, Length, original, region, analyzerI)
            allRegions.append(effectRegion)

    return allRegions


# This function inform the server to get ready for another replay
# The last parameter specifies whether we need to bring up the liberate proxy for this replay
def Replay(PcapDirectory, pacmodify, AnalyzerI):
    global Replaycounter
    Replaycounter += 1
    # Repeat the experiment for 10 times, until we get a classification result, otherwise just
    classification = None
    for i in xrange(10):
        classification = runReplay(PcapDirectory, pacmodify, AnalyzerI)
        time.sleep(10)
        if classification != None:
            break
        if i == 9:
            print "\r\n Can not get the classification result after the 10th trial, exiting"
            sys.exit()

    return classification



# This would do a full analysis on one side of the conversation
# Look into the payload by binary randomization
# If the key regions can be found in the payload
#    record those regions
def FullAnalysis(PcapDirectory, meta, Classi_Origin, Side, analyzerI):
    Analysis = {}
    for packetNum in xrange(len(meta[Side])):
        Analysis[packetNum] = []
        # Do Binary Randomization
        regions = RPanalysis(PcapDirectory, Side, packetNum + 1, meta[Side][packetNum], Classi_Origin, analyzerI)
        RPresult = ['DPI based differentiation, matching regions:', regions]
        Analysis[packetNum] = RPresult

    return Analysis


# Get the flow info into a list
# e.g. [c0,c1,s0] means the whole flow contains 2 client packet and 1 server packet
def extractMetaList(meta):
    FullList = []
    for cnt in xrange(len(meta['Client'])):
        FullList.append('c'+str(cnt))
    for cnt in xrange(len(meta['Server'])):
        FullList.append('s'+str(cnt))

    return FullList


# For the lists inside, if the two consecutive lists contain memebers that are consecutive, we combine them together
# For example, [1,2], [3,4,5], [7,8]
# Would become [1,2,3,4,5], [7,8]
def CompressLists(Alists):
    lastNum = 0
    CompressedLists = []
    for Alist in Alists:
        if Alist[0] == (lastNum + 1):
            lastList = CompressedLists.pop(-1)
            CompressedLists.append(lastList + Alist)
            lastNum = Alist[-1]
        else:
            CompressedLists.append(Alist)
            lastNum = Alist[-1]
    return CompressedLists


# Compress the meta by combining consecutive regions for extracting keywords
def CompressMeta(Meta):
    CMeta = {}
    for packetNum in Meta:
        decision = Meta[packetNum]
        # If the payload of this packet is used by DPI
        if 'DPI' in decision[0]:
            CompressedLists = CompressLists(decision[1])
            CMeta[packetNum] = CompressedLists
        # Else, do not change anything
        else:
            CMeta[packetNum] = Meta[packetNum]
    return CMeta


def ExtractKeywordServer(serverQ, Prot, ServerAnalysis):
    Prot = 'tcp'
    for P in serverQ.keys():
        if serverQ[P] != {}:
            Prot = P
    csp = serverQ[Prot].keys()[0]
    sMeta = CompressMeta(ServerAnalysis)
    # Get the keywords that are being matched on
    MatchingPackets = {}
    for Pnum in sMeta:
        keywords = []
        for Alist in sMeta[Pnum]:
            start = Alist[0]
            end = Alist[-1] + 1
            # We get the keyword from each sub field
            if Prot == 'udp':
                keyword = serverQ[Prot][csp][Pnum].payload.decode('hex')[start : end]
            else:
                keyword = serverQ[Prot][csp][Pnum].response_list[0].payload.decode('hex')[start : end]
            # keywords contains all the keywords matched in this packet
            keywords.append(keyword)
        MatchingPackets[Pnum] = keywords

    return MatchingPackets

# Extract the corresponding contents for the matching bytes
def ExtractKeywordClient(clientQ, ClientAnalysis):
    cMeta = CompressMeta(ClientAnalysis)
    # Get the keywords that are being matched on
    MatchingPackets = {}
    for Pnum in cMeta:
        keywords = []
        for Alist in cMeta[Pnum]:
            start = Alist[0]
            end = Alist[-1] + 1
            # We get the keyword from each sub field
            keyword = clientQ[Pnum].payload.decode('hex')[start : end]
            # keywords contains all the keywords matched in this packet
            keywords.append(keyword)
        MatchingPackets[Pnum] = keywords
    # We return a dictionary of packet to keywords
    # e.g. MatchingPackets = {0 : ['GET', 'Host: www.goodexample.com'], 1: ['got to be good']}
    return MatchingPackets


def setUpConfig(configs):
    configs.set('ask4analysis'     , False)
    configs.set('analyzerPort'     , 56565)
    configs.set('byExternal', True)
    configs.set('testID', '-1')
    configs.set('areaThreshold', 0.1)
    configs.set('ks2Threshold', 0.05)
    configs.set('ks2Beta', '0.90')

    configs.read_args(sys.argv)
    return configs

def main(args):

    # injectionCodes are the modifications we can use for injection
    injectionCodes = {}
    IPinjectionCodes = ['IPi1','IPi2','IPi3','IPi4','IPi5','IPi6','IPi7','IPi8','IPi9']
    injectionCodes['tcp'] = IPinjectionCodes + ['TCPi1','TCPi2','TCPi3','TCPi4','TCPi5']
    injectionCodes['udp'] = IPinjectionCodes + ['UDPi1','UDPi2','UDPi3']
    # splitCodes are the modifications we can use for splitting packets
    splitCodes = {}
    IPsplitCodes = ['IPs','IPr']
    splitCodes['tcp'] = IPsplitCodes + ['TCPs','TCPr']
    splitCodes['udp'] = IPsplitCodes + ['UDPr']

    # All the configurations used
    configs = Configs()
    configs = setUpConfig(configs)

    if args == []:
        configs.read_args(sys.argv)
    else:
        configs.read_args(args)

    configs.check_for(['pcap_folder', 'num_packets'])

    #The following does a DNS lookup and resolves server's IP address
    try:
        configs.get('serverInstanceIP')
    except KeyError:
        configs.check_for(['serverInstance'])
        configs.set('serverInstanceIP', Instance().getIP(configs.get('serverInstance')))

    PcapDirectory = configs.get('pcap_folder')

    if not PcapDirectory.endswith('/'):
        PcapDirectory = PcapDirectory + '/'

    numPackets = configs.get('num_packets')
    client_ip_file = os.path.abspath(PcapDirectory + '/client_ip.txt')

    with open(client_ip_file,'r') as c:
        client_ip = c.readline().split('\n')[0]

    permaData = PermaData()
    permaData.updateHistoryCount()
    analyzerI = AnalyzerI(configs.get('serverInstanceIP'), configs.get('analyzerPort'))

    # STEP 1
    # Check whether there is differentiation
    changeMeta, csp, Protocol, replayName, clientQ, serverQ = GetMeta(PcapDirectory, numPackets, client_ip)
    PRINT_ACTION('META DATA for The packets that we need to change' + str(changeMeta), 0)
    # Replaycounter records how many replays we ran for this analysis
    global Replaycounter
    # No modification, get original Classification
    nomodify = pickle.dumps(('Client', -1, None, None))
    PRINT_ACTION('Start to replay Original trace',0)
    Classi_Origin = Replay(PcapDirectory, nomodify, analyzerI)

    # Load the randomized trace and perform a replay to check whether DPI based classification
    PRINT_ACTION('Start to replay Randomized trace',0)
    Classi_Random = Replay(PcapDirectory[:-1] + 'Random/', nomodify, analyzerI)

    if Classi_Origin == Classi_Random:
        PRINT_ACTION('NO DPI based differentiation detected. Both original trace and randomized trace are classified the same',0)
        sys.exit()

    # STEP 2, Reverse Engineer the classifier Rule
    # PRINT_ACTION('Start reverse engineering the classification contents',0)
    # Client = FullAnalysis(PcapDirectory, changeMeta, Classi_Origin, 'Client', analyzerI)
    # # This is for testing only
    # # Client = {0:['DPI based differentiation, matching regions:', [[0,1,2,3],[98,99,100,101,102,103,104]]]}
    # #
    # Server = FullAnalysis(PcapDirectory, changeMeta, Classi_Origin, 'Server', analyzerI)
    # # This is for testing only
    # # Server = {3:['DPI based differentiation, matching regions:', [[0,1,2,3],[98,99,100,101,102,103,104]]], 0:['DPI based differentiation, matching regions:', [[0,1,2,3],[98,99,100,101,102,103,104]]]}
    # # Now we have the client side matching content used by the classifier
    # PRINT_ACTION(' Client analysis' + str(Client) + '\n\t Server analysis' + str(Server) + '\r\n Number of Tests:' + str(Replaycounter),0)
    # # If no Client Side matching content can be found, abandon, since we can not evade classification then
    # DPI = False
    # for analysis in Client:
    #     if Client[analysis][0] == 'DPI based differentiation, matching regions:':
    #         DPI = True
    # #
    # for analysis in Server:
    #     # If any of the client packets has matching field, we can run liberate
    #     if Server[analysis][0] == 'DPI based differentiation, matching regions:':
    #         DPI = True
    # #
    # if DPI == False:
    #     print Client, Server
    #     print '\r\n No DPI based differentiation has been found within the first ',numPackets, ' packets being tested, exiting'
    #     sys.exit()
    # # #
    # cKeywords = ExtractKeywordClient(clientQ, Client)
    # sKeywords = ExtractKeywordServer(serverQ, Protocol, Server)
    # print '\n\t Client side Matching Keywords',cKeywords
    # print '\n\t Server side Matching Keywords',sKeywords


if __name__=="__main__":
    main(sys.argv)
