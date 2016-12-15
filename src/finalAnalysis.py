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
    def __init__(self, userID, historyCount, replayName, extraString, date=None):
        self.userID             = str(userID)
        self.historyCount       = int(historyCount)
        self.replayName         = replayName
        self.extraString        = extraString
        self.area_vpn           = -1
        self.area_random        = -1
        self.ks2res_vpn         = -1
        self.ks2res_random      = -1
        self.ks2_ratio_vpn      = -1
        self.ks2_ratio_random   = -1
        self.xput_avg_novpn     = -1
        self.xput_avg_vpn       = -1
        self.xput_avg_random    = -1
        self.howMany            = -1
        self.replaysXputInfo    = {'NOVPN':{}, 'VPN':{}, 'RANDOM':{}}
        self.replaysRTTInfo     = {'NOVPN':{}, 'VPN':{}, 'RANDOM':{}}
        if not date:
            self.date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        else:
            self.date = convertDate(date)
    
    def tuplify(self):
        dTuple = str(tuple(map(str, [self.userID, self.historyCount, self.replayName, self.date, self.extraString, 
                                     self.area_vpn, self.ks2_ratio_vpn, self.area_random, self.ks2_ratio_random,
                                     self.xput_avg_novpn, self.xput_avg_vpn, self.xput_avg_random, self.howMany,
                                     self.ks2res_vpn, self.ks2res_random])))
        return dTuple

def finalAnalyzer(userID, historyCount, path, xputInterval, alpha):
    folder          = path + '/' + userID + '/tcpdumpsResults/'
    plotTrans       = path + '/' + userID + '/plots/xput_{}_{}_transfer.png'.format(userID, historyCount)
    regex           = '*_' + str(historyCount) + '_out.pcap'
    files           = glob.glob(folder+regex)
    doPlots         = False
    doTransferPlots = False
    pcaps           = {'NOVPN':[], 'VPN':[], 'RANDOM':[]}
    
    for f in files:
        pcap = TH.pcapName(f)
        pcaps[pcap.vpn].append(pcap)
    
    for case in pcaps:
        pcaps[case] = sorted(pcaps[case], key= lambda x: x.testCount)
    
    
    if len(pcaps['NOVPN']) == 0:
        return None
    
    pcap = pcaps['NOVPN'][0]
    
    plotFile = path + '/' + userID + '/plots/xput_{}_{}_{}_{}_{}.png'.format(userID, historyCount, pcap.extraString, pcap.replayName, pcap.incomingTime)
    
    resultObj = ResultObj(pcap.realID, pcap.historyCount, pcap.replayName, pcap.extraString, date=pcap.incomingTime)
    
    forPlot = {'NOVPN': [], 'VPN': [], 'RANDOM': []}
    
    if len(pcaps['VPN']) > 0:
        pcapsTmp = copy.deepcopy(pcaps)
        
        if len(pcapsTmp['VPN']) < len(pcapsTmp['NOVPN']):
            pcapsTmp['NOVPN'] = pcapsTmp['NOVPN'][:len(pcapsTmp['VPN'])]
        
        elif len(pcapsTmp['VPN']) > len(pcapsTmp['NOVPN']):
            pcapsTmp['VPN'] = pcapsTmp['VPN'][:len(pcapsTmp['NOVPN'])]
        
        resultFile = (path + '/' + userID + '/decisions/'+'results_{}_{}_NOVPN_VPN.pickle').format(userID, historyCount)
        forPlot1, results        = testIt(pcapsTmp, 'NOVPN', 'VPN', resultFile, xputInterval, alpha)
        forPlot['NOVPN']         = forPlot1['NOVPN']
        forPlot['VPN']           = forPlot1['VPN']
        
        resultObj.area_vpn       = results['areaTest']
        resultObj.ks2_ratio_vpn  = results['ks2ratio']
        resultObj.xput_avg_novpn = results['xputAvg1']
        resultObj.xput_avg_vpn   = results['xputAvg2']
        resultObj.ks2res_vpn     = results['ks2res']
        resultObj.howMany        = len(pcapsTmp['NOVPN'])
        resultObj.replaysXputInfo['NOVPN'] = results['replaysXputInfo']['NOVPN']
        resultObj.replaysXputInfo['VPN']   = results['replaysXputInfo']['VPN']
        resultObj.replaysRTTInfo['NOVPN']  = results['replaysRTTInfo']['NOVPN']
        resultObj.replaysRTTInfo['VPN']    = results['replaysRTTInfo']['VPN']
        doPlots = True
    
    
    if len(pcaps['RANDOM']) > 0:
        pcapsTmp = copy.deepcopy(pcaps)
        
        if len(pcapsTmp['RANDOM']) < len(pcapsTmp['NOVPN']):
            pcapsTmp['NOVPN'] = pcapsTmp['NOVPN'][:len(pcapsTmp['RANDOM'])]
        
        elif len(pcapsTmp['RANDOM']) > len(pcapsTmp['NOVPN']):
            pcapsTmp['RANDOM'] = pcapsTmp['RANDOM'][:len(pcapsTmp['NOVPN'])]
            
        resultFile = (path + '/' + userID + '/decisions/'+'results_{}_{}_NOVPN_RANDOM.pickle').format(userID, historyCount)
        
        forPlot2, results          = testIt(pcapsTmp, 'NOVPN', 'RANDOM', resultFile, xputInterval, alpha)
        forPlot['NOVPN']           = forPlot2['NOVPN']
        forPlot['RANDOM']          = forPlot2['RANDOM']

        resultObj.area_random      = results['areaTest']
        resultObj.ks2_ratio_random = results['ks2ratio']
        resultObj.xput_avg_novpn   = results['xputAvg1']
        resultObj.xput_avg_random  = results['xputAvg2']
        resultObj.ks2res_random    = results['ks2res']
        resultObj.howMany          = len(pcapsTmp['NOVPN'])
        resultObj.replaysXputInfo['NOVPN']  = results['replaysXputInfo']['NOVPN']
        resultObj.replaysXputInfo['RANDOM'] = results['replaysXputInfo']['RANDOM']
        resultObj.replaysRTTInfo['NOVPN']   = results['replaysRTTInfo']['NOVPN']
        resultObj.replaysRTTInfo['RANDOM']  = results['replaysRTTInfo']['RANDOM']
        doPlots = True
       
    if doPlots:
        plotCDFs(forPlot, pcap.replayName, plotFile)
    else:
        justPlot(pcaps, pcap.replayName, plotFile, xputInterval)
    
    if doTransferPlots:
        plotTransfers(pcaps, xputInterval, plotTrans)
    
    return resultObj

def plotCDFs(xLists, replayName, outfile):
    merged = {'NOVPN': [] , 'VPN': [] , 'RANDOM': []}
    colors = {'NOVPN': 'r', 'VPN': 'b', 'RANDOM': 'g'}
    styles = {0:'-.', 1:'-', 2:'--', 3: ':'}
    plt.clf()
    
    for case in ['NOVPN', 'VPN', 'RANDOM']:
        
        if len(xLists[case]) == 0:
            continue
        
        for testCount in sorted(xLists[case].keys()):
            merged[case] += xLists[case][testCount]
            x, y = TH.list2CDF(xLists[case][testCount])
            plt.plot(x, y, styles[testCount%4], color=colors[case], linewidth=2, label=case+'-'+str(testCount))
        
    styles = {'NOVPN':'-', 'VPN':'--', 'RANDOM': ':'}
    for case in ['NOVPN', 'VPN', 'RANDOM']:
        
        if len(merged[case]) == 0:
            continue

        x, y = TH.list2CDF(merged[case])
        plt.plot(x, y, styles[case], color='k', linewidth=2, label=case+'-megred')
    
    
    plt.axvline([1.6], linewidth=5, alpha=0.3)
    plt.axhline([0.5], linewidth=5, alpha=0.3)
    
    
    plt.ylim((0, 1.1))
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

def testIt(pcaps, what1, what2, resultFile, xputInterval, alpha, doRTT=True):
    forPlot         = {}
    merged          = {what1:[], what2:[]}
    replaysXputInfo = {what1:{}, what2:{}}
    replaysRTTinfo  = {what1:{}, what2:{}}
    
    for pcap in pcaps[what1]+pcaps[what2]:
        xputPath = pcap.path.replace('tcpdumpsResults', 'xputs')+'.pickle'
        rttPath  = xputPath + '_rtt.pickle'

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
            merged[pcap.vpn] += xput
        except KeyError:
            merged[pcap.vpn] = xput
        
        try:
            forPlot[pcap.vpn][pcap.testCount] = xput
        except:
            forPlot[pcap.vpn] = {}
            forPlot[pcap.vpn][pcap.testCount] = xput
        
        if doRTT:
            try:
                rtt = pickle.load( open(rttPath, 'r') )
                if DEBUG == 1: print 'read rtts from disk:', rttPath
                
            except IOError:
                rtt = TH.rttTshark_TCP(pcap.path, clientIP=pcap.clientIP)
                try:
                    pickle.dump( rtt, open(rttPath, 'w'), 2 )
                except Exception as e:
                    print e

                if DEBUG == 1: print 'wrote rtts from disk:', xputPath
        
        replaysXputInfo[pcap.vpn][pcap.testCount] = {'min':min(xput), 'max':max(xput), 'avg':numpy.average(xput)}
        replaysRTTinfo[pcap.vpn][pcap.testCount] = {'min':min(rtt), 'max':max(rtt), 'avg':numpy.average(rtt)}
        
    if os.path.isfile(resultFile):
        results = pickle.load( open(resultFile, 'r') )
        if DEBUG == 1: print '\t{} vs {} was already done'.format(what1, what2)
    else:
        results = TH.doTests(merged[what1], merged[what2], alpha)
        pickle.dump(results, open(resultFile, 'w') )
    
    areaTest = results[0]
    ks2ratio = results[1]
    xputAvg1 = results[4][2]
    xputAvg2 = results[5][2]
    ks2res   = results[10]
    return forPlot, {'areaTest':areaTest, 'ks2ratio':ks2ratio, 'xputAvg1':xputAvg1, 
                     'xputAvg2':xputAvg2, 'ks2res':ks2res,
                     'replaysXputInfo':replaysXputInfo,
                     'replaysRTTInfo':replaysRTTinfo}

def plotTransfers(pcaps, xputInterval, outfile):
    colors = {'NOVPN': 'r', 'VPN': 'b', 'RANDOM': 'g'}
    styles = {0:'-.', 1:'-', 2:'--', 3: ':'}
    plt.clf()
    
    for case in ['NOVPN', 'VPN', 'RANDOM']:
        for pcap in pcaps[case]:
            p           = subprocess.Popen(['tshark', '-r', pcap.path, '-qz', 'io,stat,'+str(xputInterval)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, err = p.communicate()
            x, y        = parseTsharkTransferOutput(output)
            plt.plot(x, y, styles[pcap.testCount%4], color=colors[case], linewidth=2, label=case+'-'+str(pcap.testCount))
            print case, pcap.testCount, y[-1]
#             print output
#             print x
#             print y
#             print '\n\n'
    plt.legend(loc='best')
    plt.grid()
    plt.title(pcap.replayName)
    plt.xlabel('Time (second)')
    plt.ylabel('Cumulative transfer (Mbits)')
    plt.savefig(outfile)
            
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