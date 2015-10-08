'''
#######################################################################################################
#######################################################################################################

by: Arash Molavi Kakhki (arash@ccs.neu.edu)
    Northeastern University
    
Goal: This runs the replay_client.py script "rounds" times.
      Each round consists of a VPN and a NO VPN test

Arguments:
    --pcapsFile: each line is path to a pcap_folder we want to replay
    
    --serverInstance
     
    Since this is calling replay_client.py, all the arguments necessary 
    for those scripts should be given to this one as well.

Example:
    python vpn_no_vpn.py --serverInstance=meddle --pcapsFile=pcapFolders_skype.txt --extraString=extraString --sameInstance=False
    
#######################################################################################################
#######################################################################################################
'''

import sys, commands, time, urllib2, urllib, json, multiprocessing
import replay_client, python_lib
from python_lib import *

class UI(object):
    '''
    This class contains all the methods to interact with the analyzerServer
    '''
    def __init__(self, ip, port):
        self.path = ('http://'
                     + ip 
                     + ':' 
                     + str(port) 
                     + '/Results')
        
        
    def ask4analysis(self, id, historyCount):
        '''
        Send a POST request to tell analyzer server to analyze results for a (userID, historyCount)
        
        server will send back 'True' if it could successfully schedule the job. It will
        return 'False' otherwise.
        
        This is how and example request look like:
            method: POST
            url:    http://54.160.198.73:56565/Results
            data:   userID=KSiZr4RAqA&command=analyze&historyCount=9
        '''
        data = {'userID':id, 'command':'analyze', 'historyCount':historyCount}
        res = self.sendRequest('POST', data=data)
        return res
    
    def getSingleResult(self, id, historyCount=None):
        '''
        Send a GET request to get result for a historyCount
        
        This is how an example url looks like:
            method: GET
            http://54.160.198.73:56565/Results?userID=KSiZr4RAqA&command=singleResult&historyCount=9
        '''
        data = {'userID':id, 'command':'singleResult'}
        
        if isinstance( historyCount, int ):
            data['historyCount'] = historyCount
        
        res = self.sendRequest('GET', data=data)
        return res
    
    def getMultiResults(self, id, maxHistoryCount=None, limit=None):
        '''
        Send a GET request to get maximum of 10 result.
        
        if maxHistoryCount not provided, returns the most recent results
        
        This is how an example url looks like:
            method: GET
            http://54.160.198.73:56565/Results?userID=KSiZr4RAqA&command=multiResults&maxHistoryCount=9
        '''
        data = {'userID':id, 'command':'multiResults'}
        
        if isinstance( maxHistoryCount, int ):
            data['maxHistoryCount'] = maxHistoryCount
         
        if isinstance( limit, int ):
            data['limit'] = limit
         
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
        return json.loads(res)

def toggleVPN(command):
    '''
    This function connects/disconnects the VPN
    
    NOTE: such function by nature platform dependent!
          Current script is an AppleScript and for Mac OS X.
          Need scripts for Linux and maybe Windows (urgh!) too! should be straight forward
    '''
    print commands.getoutput('./meddle_vpn.sh ' + command)

def run_one(round, tries, vpn=False):
    '''
    Runs the client script once.
        - if vpn == True: use vpn, else do directly
    '''
    if vpn:
        toggleVPN('connect')
    else:
        toggleVPN('disconnect')
    
    time.sleep(2)   #wait for VPN to toggle

    tryC = 1
    while tryC <= tries:
        p = multiprocessing.Process( target=replay_client.run )
        p.start()
        p.join()
        
        PRINT_ACTION('Done with {}. Exit code: {}'.format(Configs().get('testID'), p.exitcode), 0)
        tryC += 1
        
        #If:  successful: exitCode == 0
        #or   no permission: exitCode == 3
        if p.exitcode in [0, 3]:
            break
        #If ipFlipping: exitCode == 2
        elif p.exitcode == 2:
            Configs().set('addHeader', True)
            Configs().set('extraString', Configs().get('extraString')+'-addHeader')
            print '\n\n*****ATTENTION: there seems to be IP flipping happening. Will addHeader from now on.*****\n\n'
        
    return p.exitcode
        
def runSet():
    toggleVPN('disconnect')    
    
    configs = Configs()
    
    for i in range(configs.get('rounds')):
        
        if (i == configs.get('rounds')-1) and (not configs.get('doVPNs')) and (not configs.get('doRANDOMs')):
            configs.set('endOfTest', True)
        
        if configs.get('doNOVPNs'):
            configs.set('testID', 'NOVPN_'+str(i+1))
            print '\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
            print 'DOING ROUND: {} -- {} -- {}'.format(i+1, configs.get('testID'), configs.get('pcap_folder'))
            print '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
            exitCode = run_one(i, configs.get('tries'), vpn=False)
            
            if exitCode == 3:
                os._exit(3)
            
            time.sleep(2)
        
        if configs.get('doRANDOMs'):
            
            if (i == configs.get('rounds')-1) and (not configs.get('doVPNs')):
                configs.set('endOfTest', True)
                
            configs.set('testID', 'RANDOM_'+str(i+1))
            
            configs.set('pcap_folder', configs.get('pcap_folder')+'_random')
            print '\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
            print 'DOING ROUND: {} -- {} -- {}'.format(i+1, configs.get('testID'), configs.get('pcap_folder'))
            print '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'

            #Every set of replays MUST start with testID=NOVPN_1, this is a server side thing!
            #If NOVPN is False, we use RANDOMs are NOVPN.
            if not configs.get('doNOVPNs'):
                print '\n\tdoNOVPNs is False --> changing testID from RANDOM to NOVPN for server compatibility!\n'
                configs.set('testID', 'NOVPN_'+str(i+1))
            
            run_one(i, configs.get('tries'), vpn=False)
            configs.set('pcap_folder', configs.get('pcap_folder').replace('_random', ''))
            time.sleep(2)
        
            
        if configs.get('doVPNs'):
            if i == configs.get('rounds')-1:
                configs.set('endOfTest', True)
                
            configs.set('testID', 'VPN_'+str(i+1))
            
            if configs.get('sameInstance'):
                serverInstanceIP = configs.get('serverInstanceIP')
                configs.set('serverInstanceIP', Instance().getIP('VPN'))
            
            if configs.get('doTCPDUMP'):
                tcpdump_int = configs.get('tcpdump_int')
                configs.set('tcpdump_int', configs.get('tcpdump_int'))
#                 configs.set('tcpdump_int', 'en0')
#                 configs.set('tcpdump_int', None)
            
            print '\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
            print 'DOING ROUND: {} -- {} -- {}'.format(i+1, configs.get('testID'), configs.get('pcap_folder'))
            print '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
            run_one(i, configs.get('tries'), vpn=True)
            
            if configs.get('sameInstance') is True:
                configs.set('serverInstanceIP', serverInstanceIP)
                
            if configs.get('doTCPDUMP'):
                configs.set('tcpdump_int', tcpdump_int)
        
        print 'Done with round :{}\n'.format(i+1)
    
    toggleVPN('disconnect')
    
def main():
    PRINT_ACTION('Reading configs file and args)', 0)
    configs = Configs()
    configs.set('sidechannel_port' , 55555)
    configs.set('serialize'        , 'pickle')
    configs.set('timing'           , True)
    configs.set('jitter'           , True)
    configs.set('doTCPDUMP'        , False)
    configs.set('result'           , False)
    configs.set('iperf'            , False)
    configs.set('multipleInterface', False)
    configs.set('sendMobileStats'  , False)
    configs.set('sameInstance'     , True)
    configs.set('resultsFolder'    , 'Results')
    configs.set('jitterFolder'     , 'jitterResults')
    configs.set('tcpdumpFolder'    , 'tcpdumpsResults')
    configs.set('byExternal'       , True)
    configs.set('skipTCP'          , False)
    configs.set('addHeader'        , True)
    configs.set('maxIdleTime'      , 60)
    configs.set('endOfTest'        , False)
    configs.set('tries'            , 1)
    configs.set('rounds'           , 3)
    configs.set('doNOVPNs'         , True)
    configs.set('doVPNs'           , True)
    configs.set('doRANDOMs'        , False)
    
    configs.set('analyzerPort'     , 56565)
    
    configs.read_args(sys.argv)
    configs.check_for(['pcapsFile'])
    
    #The except does a DNS lookup and resolves server's IP address
    #This is essential to be done only ONCE to assure that client
    #contacts the same server throughout the entire test (i.e. DNS load balancer
    #does not provide different servers throughout the test)
    try:
        configs.get('serverInstanceIP')
    except KeyError:
        configs.check_for(['serverInstance'])
        configs.set('serverInstanceIP', Instance().getIP(configs.get('serverInstance')))
    
    if configs.get('doTCPDUMP'):
        configs.check_for(['tcpdump_int'])
        
    if not configs.get('multipleInterface'):
        configs.set('publicIP', '')
    else:
        configs.check_for(['publicIP'])
    
    try:
        configs.get('pcap_folder')
        print '\nYou should not provide \"--pcap_folder\" to this script.\n'
        print '\nUse \"--pcaps\" to feed all your pcap folders (comma separated)\n'
        sys.exit()
    except:
        pass
    
    try:
        configs.get('extraString')
    except:
        print '\nYou should provide \"--extraString\" to this script.'
        print 'Use some indicative name, like the name of mobile provider, e.g. Tmobile, ATT\n'
        sys.exit()
    
    if (not configs.get('doNOVPNs')) and (not configs.get('doRANDOMs')):
        print '\ndoNOVPNs and doRANDOMSs cannot both be False. One should be True!!!'
        sys.exit()
    
    configs.show_all()
    
    PRINT_ACTION('Creating results folders', 0)
    if not os.path.isdir(configs.get('resultsFolder')):
        os.makedirs(configs.get('resultsFolder'))
    
    configs.set('jitterFolder', configs.get('resultsFolder') + '/' + configs.get('jitterFolder'))
    if not os.path.isdir(configs.get('jitterFolder')):
        os.makedirs(configs.get('jitterFolder'))
    
    configs.set('tcpdumpFolder', configs.get('resultsFolder') + '/' + configs.get('tcpdumpFolder'))    
    if not os.path.isdir(configs.get('tcpdumpFolder')):
        os.makedirs(configs.get('tcpdumpFolder'))
    
    
    PRINT_ACTION('Firing off ...', 0)
    ui        = UI(configs.get('serverInstanceIP'), configs.get('analyzerPort'))
    permaData = PermaData()
#     print ui.getSingleResult('yrTouJjKY0', 27)
#     print ui.getMultiResults('yrTouJjKY0', maxHistoryCount=27, limit=2 )
#     print ui.ask4analysis('BFIOM5F6J9', 1)
#     sys.exit()
    
    with open(configs.get('pcapsFile'), 'r') as f:
        lines = f.readlines()
        for pcapFolder in lines:
            pcapFolder = pcapFolder.strip()
            
            print '\tDoing:', pcapFolder
            
            configs.set('pcap_folder', pcapFolder)
            
            permaData.updateHistoryCount()
            runSet()
            configs.set('endOfTest', False)
            PRINT_ACTION('Asking for analysis', 0)
            print '\t', ui.ask4analysis(permaData.id, permaData.historyCount)
    
if __name__=="__main__":
    main()