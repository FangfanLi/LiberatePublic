import subprocess, numpy, datetime
import matplotlib
import copy
matplotlib.use('Agg')
import sys, glob, pickle, os, time
sys.path.append('testHypothesis')
import matplotlib.pyplot as plt
import testHypothesis as TH

DEBUG = 0

def convertDate(date):
    '''
    converts '%Y-%b-%d-%H-%M-%S' to '%Y-%m-%d %H:%M:%S'
    '''
    
    date = datetime.datetime.strptime(date, "%Y-%b-%d-%H-%M-%S")
    date = date.strftime('%Y-%m-%d %H:%M:%S')
    return date

class ResultObj(object):
    def __init__(self, userID, historyCount, testID, replayName, extraString, date=None):
        self.userID             = str(userID)
        self.historyCount       = int(historyCount)
        self.testID             = int(testID)
        self.replayName         = replayName
        self.extraString        = extraString
        self.xput_avg_original  = -1
        self.xput_avg_test      = -1
        self.area_test          = -1
        self.ks2_ratio_test     = -1
        self.ks2dVal            = -1
        self.ks2pVal            = -1
        if not date:
            self.date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        else:
            self.date = convertDate(date)
    
    def tuplify(self):
        dTuple = str(tuple(map(str, [self.userID, self.historyCount, self.testID, self.replayName, self.date, self.extraString,
                                     self.xput_avg_original, self.xput_avg_test,
                                     self.area_test, self.ks2_ratio_test, self.ks2dVal, self.ks2pVal])))
        return dTuple

def finalAnalyzer(userID, historyCount, testID, path, xputBuckets, alpha):
    folder          = path + '/' + userID + '/tcpdumpsResults/'
    regexTarget     = '*_' + str(historyCount) + '_' + str(testID) + '_out.pcap'
    regexOriginal   = '*_' + str(historyCount) + '_' + str(0) + '_out.pcap'
    fileTarget      = glob.glob(folder+regexTarget)
    fileOriginal    = glob.glob(folder+regexOriginal)

    pcapT = TH.pcapName(fileTarget[0])
    pcapO = TH.pcapName(fileOriginal[0])

    plotFile = path + '/' + userID + '/plots/xput_{}_{}_{}_{}_{}_{}.png'.format(userID, historyCount, testID, pcapO.extraString, pcapO.replayName, pcapO.incomingTime)

    resultObj = ResultObj(pcapO.realID, pcapO.historyCount, testID, pcapO.replayName, pcapO.extraString, date=pcapO.incomingTime)

        
    resultFile = (path + '/' + userID + '/decisions/'+'results_{}_{}_{}.pickle').format(userID, historyCount,testID)
    forPlot, results        = testIt(pcapT, pcapO, resultFile, xputBuckets, alpha)
        
    resultObj.area_test      = results['areaTest']
    resultObj.ks2_ratio_test = results['ks2ratio']
    resultObj.xput_avg_original = results['xputAvg1']
    resultObj.xput_avg_test   = results['xputAvg2']
    resultObj.ks2dVal = results['ks2dVal']
    resultObj.ks2pVal   = results['ks2pVal']

    try:
        plotCDFs(forPlot, plotFile)
    except Exception as e:
        print '\r\n ########### Error when plotting CDF #########',e

    
    return resultObj

def plotCDFs(xLists, outfile):
    colors = ['r', 'b', 'g', 'b']
    styles = {0:'-.', 1:'-', 2:'--', 3: ':'}
    plt.clf()

    i      = -1
    j      = 0
    for traceName in xLists.keys():
        i       += 1
        j       += 3
        x, y     = TH.list2CDF(xLists[traceName])
        plt.plot(x, y, '-', color=colors[i%len(colors)], linewidth=2, label=traceName)

    plt.ylim((0, 1.1))

    plt.axvline([1.6], linewidth=5, alpha=0.3)
    plt.axhline([0.5], linewidth=5, alpha=0.3)
    

    plt.legend(loc='best', prop={'size':8})
    plt.grid()
    plt.title( outfile.rpartition('/')[2] )
    plt.xlabel('Xput (Mbits/sec)')
    plt.ylabel('CDF')
    plt.savefig(outfile)

def justPlot(pcaps, replayName, outfile, xputInterval):
    forPlot = {'NOVPN':[], 'VPN':[], 'RANDOM':[]}
    
    for pcap in pcaps['NOVPN']+pcaps['VPN']+pcaps['RANDOM']:
        xputPath = pcap.path.replace('tcpdumpsResults', 'xputs')+'.pickle'
        
        try:
            (xput, dur) = pickle.load( open(xputPath, 'r') )
            if DEBUG == 1: print 'read xputs from disk:', xputPath
            
        except IOError:
            if pcap.vpn == 'VPN':
                (xput, dur) = TH.adjustedXput( pcap.path, xputInterval, addOH=True )
            else:
                (xput, dur) = TH.adjustedXput( pcap.path, xputInterval, addOH=False )
            try:
                pickle.dump( (xput, dur), open(xputPath, 'w'), 2 )
            except Exception as e:
                print e
            
            if DEBUG == 1: print 'wrote xputs from disk:', xputPath
            
        try:
            forPlot[pcap.vpn][pcap.testCount] = xput
        except:
            forPlot[pcap.vpn] = {}
            forPlot[pcap.vpn][pcap.testCount] = xput
    
    plotCDFs(forPlot, replayName, outfile)

def testIt(pcapT, pcapO, resultFile, xputBuckets, alpha, doRTT=True):
    forPlot         = {}

    xputPathT = pcapT.path.replace('tcpdumpsResults', 'xputs')+'.pickle'
    xputPathO = pcapO.path.replace('tcpdumpsResults', 'xputs')+'.pickle'

    try:
        (xputT, durT) = pickle.load(open(xputPathT, 'r') )
        if DEBUG == 1: print 'read xputs from disk:', xputPathT

    except IOError:
        (xputT, durT) = TH.adjustedXput( pcapT.path, xputBuckets, addOH=False )

        try:
            pickle.dump((xputT, durT), open(xputPathT, 'w'), 2 )
        except Exception as e:
            print e

    try:
        (xputO, durO) = pickle.load(open(xputPathO, 'r') )
        if DEBUG == 1: print 'read xputs from disk:', xputPathO

    except IOError:
        (xputO, durO) = TH.adjustedXput(pcapO.path, xputBuckets, addOH=False )

        try:
            pickle.dump((xputO, durO), open(xputPathO, 'w'), 2 )
        except Exception as e:
            print e


    if os.path.isfile(resultFile):
        results = pickle.load( open(resultFile, 'r') )
    else:
        results = TH.doTests(xputO, xputT, alpha)
        pickle.dump(results, open(resultFile, 'w') )

    forPlot['Exposed'] = xputO
    forPlot['Hidden'] = xputT


    areaTest = results[0]
    ks2ratio = results[1]
    xputAvg1 = results[4][2]
    xputAvg2 = results[5][2]
    ks2dVal = results[9]
    ks2pVal = results[10]
    return forPlot, {'areaTest':areaTest, 'ks2ratio':ks2ratio, 'xputAvg1':xputAvg1, 
                     'xputAvg2':xputAvg2, 'ks2dVal':ks2dVal, 'ks2pVal':ks2pVal}

            
def parseTsharkTransferOutput(output):
    '''
    ************ WORKS WITH tshark 1.12.1 ONLY ************
    '''
    x = []
    y = []
    lines       = output.splitlines()
    
    total = 0
    
    for l in lines:
        if '<>' not in l:
            continue
        
        l      = l.replace('|', '')
        l      = l.replace('<>', '')
        parsed = map(float, l.split())
        end    = parsed[1]
        bytes  = parsed[-1]
        
        total += bytes 
        
        x.append(end)
        y.append(total)
        
    #converting to Mbits/sec
    y = map(lambda z: z/1000000.0, y)
    
    return x, y 

# finalAnalyzer('l31u73jkx2', 2, '/Users/arash/Downloads/H2O_NY', 0.25, 0.95)