'''
by:    Arash Molavi Kakhki
       arash@ccs.neu.edu
       Northeastern University
       
       
USAGE:
    sudo python replay_analyzerServer.py --port=56565 --ConfigFile=configs_local.cfg 
    
    IMPORTANT NOTES: always run in sudo mode
    
''' 

import sys, multiprocessing, json, datetime, logging
import tornado.ioloop, tornado.web
from python_lib import *
import db as DB
sys.path.append('testHypothesis')
import testHypothesis as TH
import finalAnalysis as FA

db     = None
POSTq  = multiprocessing.Queue()
logger = logging.getLogger('replay_analyzer')

def processResult(results):
    # Only if ks2ration > ks2Beta (this is the confidence interval) the ks2 result is trusted, otherwise only the area test is used
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

    # Should only be one result since unique (userID, historyCount, testID)
    result = results[0]
    areaT = Configs().get('areaThreshold')
    ks2Beta  = Configs().get('ks2Beta')
    ks2T  = Configs().get('ks2Threshold')

    outres = {'userID'    : result['userID'],
              'historyCount': result['historyCount'],
              'replayName'  : result['replayName'],
              'date'        : result['date'],
              'xput_avg_original' : result['xput_avg_original'],
              'xput_avg_test': result['xput_avg_test'],
              'area_test' : result['area_test'],
              'ks2pVal': result['ks2pVal']}

    outres['against'] = 'test'

    Negative = False
    # if the controlled flow has less throughput
    if result['xput_avg_test'] < result['xput_avg_original']:
        Negative = True

    # ks2_ratio test is problematic, sometimes does not give the correct result even in the obvious cases, not using it so far
    # 1.Area test does not pass and 2.With confidence level ks2Beta that the two distributions are the same
    # Then there is no differentiation
    if (result['area_test'] < areaT) and (result['ks2pVal'] > ks2T):
        outres['diff'] = 0
        outres['rate'] = 0
    # 1.Area test does pass and 2.With confidence level ks2Beta that the two distributions are not the same
    # Then there is differentiation
    elif (result['area_test'] > areaT) and (result['ks2pVal'] < ks2T):
        outres['diff'] = 2
        outres['rate'] = (result['xput_avg_test'] - result['xput_avg_original'])/min(result['xput_avg_original'], result['xput_avg_test'])
    # Else inconclusive
    else:
        outres['diff'] = 1
        outres['rate'] = 0

    if Negative:
        outres['diff'] = - outres['diff']
        outres['rate'] = - outres['rate']
        
    return outres

def analyzer(args, resultsFolder, xputBuckets, alpha):
    global db
    
    LOG_ACTION(logger, 'analyzer:'+str(args))
    args = json.loads(args)
    
    resObj = FA.finalAnalyzer(args['userID'][0], args['historyCount'][0], args['testID'][0], resultsFolder, xputBuckets, alpha)

    try:
        db.insertResult(resObj)
        # db.updateReplayXputInfo(resObj)
    except Exception as e:
        LOG_ACTION(logger, 'Insertion exception:'+str(e), level=logging.ERROR)
    
def jobDispatcher(q, processes=4):
    resultsFolder = Configs().get('resultsFolder')
    xputBuckets  = Configs().get('xputBuckets')
    alpha         = Configs().get('alpha')
    pool = multiprocessing.Pool(processes=processes)
    while True:
        args = q.get()
        pool.apply_async(analyzer, args=(args, resultsFolder, xputBuckets, alpha,))

class myJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            obj = obj.isoformat()
        else:
            obj = super(myJsonEncoder, self).default(obj)
        return obj    

def getHandler(args):
    '''
    Handles GET requests.
    
    Basically gets a request (i.e. MySQL job), does appropriate DB lookup, and returns results.
    
    If something wrong with the job, returns False. 
    '''
    global db
    
    try:
        command = args['command'][0]
    except:
        return json.dumps({'success':False, 'error':'command not provided'})
    
    try:
        userID       = args['userID'][0]
    except KeyError as e:
        return json.dumps({'success':False, 'missing':str(e)})
    
    if command == 'singleResult':
        try:
            historyCount = int(args['historyCount'][0])
            testID = int(args['testID'][0])
        except Exception as e:
            return json.dumps({'success':False, 'error':str(e)})
        
        try:
            # provide raw result to the client, let client decide whether differentiation,
            # give flexibility in setting parameters
            response = db.getSingleResult(userID, historyCount, testID)
            # response = processResult(response)
            # Should only be one result since unique (userID, historyCount, testID)
            return json.dumps({'success':True, 'response':response[0]}, cls=myJsonEncoder)
        except Exception as e:
            return json.dumps({'success':False, 'error':str(e)})

    # Return the latest threshold for both area test and ks2 test
    elif command == 'defaultSetting':
        # Default setting for the client
        areaThreshold = 0.1
        ks2Threshold = 0.05
        ks2Ratio = 0.95
        return json.dumps({'success':True, 'areaThreshold':str(areaThreshold), 'ks2Threshold':str(ks2Threshold),
                           'ks2Ratio':str(ks2Ratio)}, cls=myJsonEncoder)
    
    else:
        return json.dumps({'success':False, 'error':'unknown command'})
    
def postHandler(args):
    '''
    Handles POST requests.
    
    Basically puts the job on the queue and return True.
    
    If something wrong with the job, returns False. 
    '''
    try:
        command = args['command'][0]
    except:
        return json.dumps({'success':False, 'error':'command not provided'})
    
    try:
        userID       = args['userID'][0]
        historyCount = int(args['historyCount'][0])
        testID = int(args['testID'][0])
    except KeyError as e:
        return json.dumps({'success':False, 'missing':str(e)})
    
    if command == 'analyze':
        POSTq.put(json.dumps(args))
    else:
        return json.dumps({'success':False, 'error':'unknown command'})
    
    return json.dumps({'success':True})

class Results(tornado.web.RequestHandler):
    
    @tornado.web.asynchronous
    def get(self):
        pool = self.application.settings.get('GETpool')
        args = self.request.arguments
        LOG_ACTION(logger, 'GET:'+str(args))
        pool.apply_async(getHandler, (args,), callback=self._callback)
    
    def post(self):
        args = self.request.arguments
        LOG_ACTION(logger, 'POST:'+str(args))
        self.write( postHandler(args) )
        
    @tornado.web.asynchronous
    def post_old(self):
        pool = self.application.settings.get('POSTpool')
        args = self.request.arguments
        pool.apply_async(postHandler, (args,), callback=self._callback)
    
    def _callback(self, response):
        LOG_ACTION(logger, '_callback:'+str(response))
        self.write(response)
        self.finish()

def main():
    
    global db
    
    # PRINT_ACTION('Checking tshark version', 0)
    # TH.checkTsharkVersion('1.8')
    
    configs = Configs()
    configs.set('GETprocesses' , 4)
    configs.set('ANALprocesses', 4)
    configs.set('xputInterval' , 0.25)
    configs.set('alpha'        , 0.95)
    configs.set('mainPath'     , 'RecordReplay/')
    configs.set('resultsFolder', 'ReplayDumps/')
    configs.set('logsPath'     , 'logs/')
    configs.set('analyzerLog'  , 'analyzerLog.log')
    configs.read_args(sys.argv)
    configs.check_for(['analyzerPort'])
    
    PRINT_ACTION('Configuring paths', 0)
    configs.set('resultsFolder' , configs.get('mainPath')+configs.get('resultsFolder'))
    configs.set('logsPath'      , configs.get('mainPath')+configs.get('logsPath'))
    configs.set('analyzerLog'   , configs.get('logsPath')+configs.get('analyzerLog'))
    
    PRINT_ACTION('Setting up logging', 0)
    if not os.path.isdir(configs.get('logsPath')):
        os.makedirs(configs.get('logsPath'))

    createRotatingLog(logger, configs.get('analyzerLog'))
    
    configs.show_all()
    
    db = DB.DB()
    
    LOG_ACTION(logger, 'Starting server. Configs: '+str(configs), doPrint=False)
    
    p = multiprocessing.Process(target=jobDispatcher, args=(POSTq,), kwargs={'processes':configs.get('ANALprocesses')})
    p.start()
    
    application = tornado.web.Application([(r"/Results", Results),
                                           ])
    
    application.settings = {'GETpool'  : multiprocessing.Pool(processes=configs.get('GETprocesses')),
                            'debug': True,
                            }
    
    application.listen(configs.get('analyzerPort'))
    
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()
