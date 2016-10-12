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
    areaT = Configs().get('areaThreshold')
    ks2T  = Configs().get('ks2Threshold')
    
    output = []
    for res in results:
        outres = {'userID'      : res['userID'], 
                  'historyCount': res['historyCount'], 
                  'replayName'  : res['replayName'],
                  'date'        : res['date']}
        
        if res['area_vpn'] != -1:
            outres['against'] = 'vpn'
            
            #no differentiation
            #first IF clause is temporary --> cases where NoVPN has better performance than VPN,
            #do not report differentiation to avoid false positive due to VPN overhead
            if res['xput_avg_vpn'] < res['xput_avg_novpn']:
                outres['rate'] = 0
                outres['diff'] = -1
            elif (res['area_vpn'] < areaT) and (1-res['ks2_ratio_vpn'] < ks2T):     #both saying no differentiation
                outres['rate'] = 0
                outres['diff'] = -1
            
            #differentiation
            elif (areaT <= res['area_vpn']) and (1-res['ks2_ratio_vpn'] >= ks2T):       #both saying differentiation
                outres['rate'] = (res['xput_avg_novpn'] - res['xput_avg_vpn'])/min(res['xput_avg_novpn'], res['xput_avg_vpn'])
                outres['diff'] = 1
                
            #inconclusive
            else:
                outres['rate'] = 0
                outres['diff'] = 0
        
        elif res['area_random'] != -1:
            outres['against'] = 'random'
            
            #no differentiation
            #first IF clause is temporary --> cases where NoVPN has better performance than VPN,
            #do not report differentiation to avoid false positive due to VPN overhead
            if res['xput_avg_random'] < res['xput_avg_novpn']:
                outres['rate'] = 0
                outres['diff'] = -1
            elif (res['area_random'] < areaT) and (1-res['ks2_ratio_random'] < ks2T):       #both saying no differentiation
                outres['rate'] = 0
                outres['diff'] = -1
            
            #differentiation
            elif (areaT <= res['area_random']) and (1-res['ks2_ratio_random'] >= ks2T):     #both saying differentiation
                outres['rate'] = (res['xput_avg_novpn'] - res['xput_avg_random'])/min(res['xput_avg_novpn'], res['xput_avg_random'])
                outres['diff'] = 1
        
        output.append(outres)
        
    return output

def analyzer(args, resultsFolder, xputInterval, alpha):
    global db
    
    LOG_ACTION(logger, 'analyzer:'+str(args))
    args = json.loads(args)
    
    resObj = FA.finalAnalyzer(args['userID'][0], args['historyCount'][0], resultsFolder, xputInterval, alpha)
    
    try:
        db.insertResult(resObj)
        db.updateReplayXputInfo(resObj)
    except Exception as e:
        LOG_ACTION(logger, 'Insertion exception:'+str(e), level=logging.ERROR)
    
def jobDispatcher(q, processes=4):
    resultsFolder = Configs().get('resultsFolder')
    xputInterval  = Configs().get('xputInterval')
    alpha         = Configs().get('alpha')
    pool = multiprocessing.Pool(processes=processes)
    while True:
        args = q.get()
        pool.apply_async(analyzer, args=(args, resultsFolder, xputInterval, alpha,))

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
        except KeyError:
            historyCount = None
        
        try:
            response = db.getSingleResult(userID, historyCount=historyCount)
            response = processResult(response)
            return json.dumps({'success':True, 'response':response}, cls=myJsonEncoder)
        except Exception as e:
            return json.dumps({'success':False, 'error':str(e)})
    
    elif command == 'multiResults':
        try:
            maxHistoryCount = int(args['maxHistoryCount'][0])
        except KeyError:
            maxHistoryCount = None
        
        try:
            limit = int(args['limit'][0])
        except KeyError:
            limit = None
        
        try:
            response = db.getMultiResults(userID, maxHistoryCount=maxHistoryCount, limit=limit)
            response = processResult(response)
            return json.dumps({'success':True, 'response':response}, cls=myJsonEncoder)
        except Exception as e:
            return json.dumps({'success':False, 'error':str(e)})
    
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
    
    PRINT_ACTION('Checking tshark version', 0)
    TH.checkTsharkVersion('1.8')
    
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
