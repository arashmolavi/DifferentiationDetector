'''
#######################################################################################################
#######################################################################################################
Arash Molavi Kakhki (arash@ccs.neu.edu)
Northeastern University

Goal: this file includes functions for KS2 and 

Usage:

#######################################################################################################
#######################################################################################################
'''
import matplotlib
matplotlib.use('Agg')
import sys
sys.path.append('..')
import subprocess, random, numpy
import python_lib
import matplotlib.pyplot as plt
import scipy.stats
from scipy.stats import ks_2samp
from scipy import interpolate, integrate

DEBUG = 0


class pcapName(object):
    def __init__(self, pcapFile):
        
        self.path = pcapFile
        
        if pcapFile[-1] == '/':
            pcapFile = pcapFile[:-1]
        
        if not pcapFile.endswith('.pcap'):
            self.pcap = False
            return
        
        self.pcap = True
        
        pcapFile = pcapFile.rpartition('/')[2]

        if pcapFile.endswith('_out.pcap'):
            self.out = True
        else:
            self.out = False
        
        info              = pcapFile.split('_')
        self.takenAt      = info[1]
        self.realID       = info[2]
        self.clientIP     = info[3]
        self.replayName   = info[4]
        self.id           = info[5]
        self.incomingTime = info[6]
        self.vpn          = info[7]        
        self.testCount    = int(info[8])
        self.extraString  = info[9]
        self.historyCount = info[10]
        self.testID       = self.vpn + '_' + str(self.testCount)

def checkTsharkVersion(targetVersion, exit=True):
    p           = subprocess.Popen(['tshark', '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = p.communicate()
    version     = output.partition('\n')[0].split()[1]
    
    if version.startswith(targetVersion):
        return True
    
    print 'Your tshark version is: {}. Please install version {}'.format(version, targetVersion)
    if exit is True:
        sys.exit()
    
    return False

def parseTsharkXputOutput(output):
    '''
    ************ WORKS WITH tshark 1.12.1 ONLY ************
    
    Takes the output of tshark xput command, i.e. tshark -qz io,stat,interval 
    and parses the results into an ordered list 
    '''
    data_points = []
    lines       = output.splitlines()
    end         = lines[4].partition('Duration:')[2].partition('secs')[0].replace(' ', '')
    lines[-2]   = lines[-2].replace('Dur', end)
    
    for l in lines:
        if '<>' not in l:
            continue
        
        l      = l.replace('|', '')
        l      = l.replace('<>', '')
        parsed = map(float, l.split())
        dur    = float(parsed[1]) - float(parsed[0])
        try:
            xput = round(float(parsed[-1])/dur, 2)
        except ZeroDivisionError:
            continue
        data_points.append(xput)
    
    #converting to Mbits/sec
    data_points = map(lambda x: x*8/1000000.0, data_points)
    
    return data_points, end

def xputTshark(pcapFile, xputInterval):
    '''
    Given a pcap the calculates total xput stats.
    '''
    
    p              = subprocess.Popen(['tshark', '-r', pcapFile, '-qz', 'io,stat,'+str(xputInterval)+',not tcp.analysis.retransmission'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err    = p.communicate()
    xputList, end  = parseTsharkXputOutput(output)
    return xputList, end

def addOverhead(x, ethOnly=False):
    ethernetOH = 14 + 0
    
    y = x + ethernetOH
    
    if not ethOnly:
        y += (16 - (x % 16)) + 64

    return y

def adjustedXput(pcapPath, xputInterval, addOH=False, ethOnly=True):
    command = ['tshark', '-r', pcapPath, '-T', 'fields', 
               '-e', 'frame.number', 
               '-e', 'frame.protocols', 
               '-e', 'frame.time_relative', 
               '-e', 'frame.len', 
               '-e', 'tcp.analysis.retransmission',
               ]
     
    p              = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err    = p.communicate()

    xput = []
    
    total = 0.0
    all   = 0
    i     = 1
    
    for l in output.splitlines():
        l = l.split()
        
        #Skip retransmissions
        try:
            l[4]
            continue
        except:
            pass
        
        ts = float(l[2])
        b  = float(l[3])
        
        if addOH:
            b  = addOverhead(b, ethOnly=ethOnly)
        
        if ts <= i*xputInterval:
            total += b
            all   += b
        else:
            xput.append(total/xputInterval)
            total = b
            i += 1
            
        
    xput.append(total/(ts-(i-1)*xputInterval))
    
    #Make it Mbits/sec
    xput = map(lambda x: x*8/1000000.0, xput)
    
    return xput, ts

def rttTshark_TCP(pcapFile, serverIP=None, clientIP=None):
    '''
    IMPORTANT NOTE1: everything is running on PCAPs captured on the server-side,
                    hence RTT for client2server direction are extremely low and
                    does not make sense and should be ignored.
                    So for frames which we have an 'tcp.analysis.ack_rtt' for, i.e. ACK frames,
                    source IP should be client's IP (meaning client is ACKing)
    IMPORTANT NOTE2: We need to toss retransmissions first                 
    '''
    
    if (clientIP is None) and (serverIP is None):
        print 'Please provide either client or server IP'
        sys.exit()
    
    cmd = ['tshark', '-r', pcapFile, '-T', 'fields',  '-E', 'separator=/t', '-e', 'ip.src', '-e', 'tcp.analysis.ack_rtt']
    p           = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#     p           = subprocess.Popen(cmd)
    output, err = p.communicate()
#     print output
#     print 'err:', err
    
    rttList = []
     
    for l in output.splitlines():
        l     = l.split('\t')
        srcIP = l[0]
        
        if serverIP is not None:
            if srcIP == serverIP:
                continue 
        
        if clientIP is not None:
            if srcIP != clientIP:
                continue 
        
        try:
            rtt = float(l[1])
        except:
            continue
        
        rttList.append(rtt)
    
    return rttList

def list2CDF(xput):
    xput = sorted(xput)
    
    x   = [0]
    y   = [0]
    
    for i in range(len(xput)):
        x.append(xput[i])
        y.append(float(i+1)/len(xput))
    
    return x, y

def sampleKS2(list1, list2, alpha=0.95, sub=0.5, r=100):
    '''
    Taken from NetPolice paper:
    
    This function uses Jackknife, a commonly-used non-parametric re-sampling method, 
    to verify the validity of the K-S test statistic. The idea is to randomly select 
    half of the samples from the two original input sets and apply the K-S test on 
    the two new subsets of samples. This process is repeated r times. If the results 
    of over B% of the r new K-S tests are the same as that of the original test, we 
    conclude that the original K-S test statistic is valid.
    '''

    results = []
    accept  = 0.0
    
    for i in range(r):
        sub1 = random.sample( list1, int(len(list1)*sub) )
        sub2 = random.sample( list2, int(len(list2)*sub) )
        res  = ks_2samp(sub1, sub2)
        results.append( res )
        
        pVal = res[1]
        
        if pVal > (1-alpha):
            accept += 1
    
    dVal_avg = numpy.average([x[0] for x in results])
    pVal_avg = numpy.average([x[1] for x in results])
    
    return [dVal_avg, pVal_avg, accept/r, results]
       
def doTests(list1, list2, alpha=0.95):
    x1, y1 = list2CDF(list1)
    f1     = interpolate.interp1d(y1, x1)

    x2, y2 = list2CDF(list2)
    f2     = interpolate.interp1d(y2, x2)
    
    (xputMax1, xputMin1, xputAvg1, xputMed1, xputStd1) = (max(list1), min(list1), numpy.average(list1), numpy.median(list1), numpy.std(list1))
    (xputMax2, xputMin2, xputAvg2, xputMed2, xputStd2) = (max(list2), min(list2), numpy.average(list2), numpy.median(list2), numpy.std(list2)) 
    diffFunc           = lambda x: abs(f1(x)-f2(x))
    (area, err)        = integrate.quad(diffFunc, 0.001, 1, limit=1000) 
    xputMin             = min(list1+list2)
    areaOvar           = float(area) / min(xputMax1, xputMax2)
    (ks2dVal, ks2pVal) = ks_2samp(list1, list2)
    [dVal_avg, pVal_avg, ks2AcceptRatio, KS2results] = sampleKS2(list1, list2, alpha=alpha)
    
    return [areaOvar, ks2AcceptRatio, area, err, 
            (xputMax1, xputMin1, xputAvg1, xputMed1, xputStd1), 
            (xputMax2, xputMin2, xputAvg2, xputMed2, xputStd2), 
            xputMin, dVal_avg, pVal_avg, ks2dVal, ks2pVal, KS2results]

def main():
    
    adjustedXput(sys.argv[1], 0.25)
    sys.exit()
    
    configs = python_lib.Configs()
    configs.set('xputInterval', 0.25)
    configs.read_args(sys.argv)
    configs.check_for(['serverIP'])
    
    print 'xputInterval:', configs.get('xputInterval')
    
    PRINT_ACTION('Checking tshark version', 0)
    checkTsharkVersion('1.12')
    
    font = {'family' : 'arial', 'weight' : 'bold', 'size'   : 22}
    matplotlib.rc('font', **font)
    f, (ax1, ax2) = plt.subplots(1, 2, sharey=True)
    
    xputs = {}
    rtts  = {}
    
    for pcap in sys.argv[2:]:
        
        print '\tParsing:', pcap
        xput, end    = xputTshark(pcap, configs.get('xputInterval'))
        rtt          = rttTshark_TCP(pcap, serverIP=configs.get('serverIP'))
        xputX, xputY = list2CDF(xput)
        rttX, rttY   = list2CDF(rtt)
                
        xputs[pcap]  = xput
        rtts[pcap]   = rtt
        
        ax1.plot(xputX, xputY, label=pcap, linewidth=4)
        ax2.plot(rttX, rttY, label=pcap, linewidth=4)
    
    for i in range(len(xputs)):
        for j in range(i+1, len(xputs)):
            k1 = xputs.keys()[i]
            k2 = xputs.keys()[j]
             
            xput1 = xputs[ k1 ]
            xput2 = xputs[ k2 ]
             
            rtt1 = rtts[ k1 ]
            rtt2 = rtts[ k2 ]
            
            print '\n\tDoing tests for:', k1, k2
            print '\t\tXput:\t', doTests(xput1, xput2)[:-1]
            print '\t\tRTT:\t', doTests(rtt1, rtt2)[:-1]

    ax1.set_title('Xput')
    ax1.set_xlabel('xput (Mbits/sec)')
    plt.setp(ax1.get_xticklabels(), rotation=45)
    ax1.grid(True)
    
    ax2.set_title('RTT (TCP -- server2client)')
    ax2.grid(True)    
    plt.setp(ax2.get_xticklabels(), rotation=45)
    
    ax2.set_xscale('log')    
    
    plt.legend(loc='lower right')
    plt.suptitle('xputInterval='+str(configs.get('xputInterval'))+'secs')
    plt.show()
    
if __name__=="__main__":
    main()
