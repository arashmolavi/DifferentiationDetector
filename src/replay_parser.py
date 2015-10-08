'''
#######################################################################################################
#######################################################################################################
Arash Molavi Kakhki (arash@ccs.neu.edu)
Northeastern University

Goal: client replay script

Usage:
    python replay_parser.py --pcap_folder=[]

Mandatory arguments:

    pcap_folder: This is the folder containing pcap file and client_ip.txt


Ignored streams:
    - Local (private) IPs
    - Apple IPs (happens when recording on an Apple product, e.g. iPhone):
        - 17.154.239.13, 17.172.239.39, 17.154.239.48, ... (check ipIgnoreList)
    - Apple static:
        - contains this:
                GET /connectivity.txt HTTP/1.1
                Host: static.ess.apple.com:80
        -can't filter using IP address, because it's hosted on Akamai
    

#######################################################################################################
#######################################################################################################
'''


import sys, os, pickle, copy, mimetools, StringIO, email, re, random, string
import python_lib
from python_lib import *

DEBUG = 2
ipIgnoreList = ['017.154.239.013', '017.154.239.023', '017.172.239.039', '017.154.239.048', '017.173.255.051', 
                '017.173.255.052', '017.173.255.061', '017.173.255.024', '017.173.255.072', '017.154.239.034',
                '017.154.239.049', '017.173.255.103', '017.173.066.180']

def getUDPstreamsMap(pcap_file, client_ip):
    command = 'tshark -r ' + pcap_file + ' -2 -R "udp" -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport > tmp'
    os.system(command)
    streams = set()
    with open('tmp', 'r') as f:
        for l in f:
            l = l.strip().split()
            
            if len(l) != 4:
                continue
            
            if client_ip == l[0]:
                p1 = ':'.join(l[:2])
                p2 = ':'.join(l[2:])
            elif client_ip == l[2]:
                p1 = ':'.join(l[2:])
                p2 = ':'.join(l[:2])
            else:
                continue    
            streams.add(p1+','+p2)
    os.system('rm tmp')
    return streams

def createPacketMeta(pcapFile, outFile):
    command = ' '.join(['tshark -r', pcapFile, 
                        '-2 -R "not tcp.analysis.retransmission"',
                        '-T fields', 
                        '-e frame.number', '-e frame.protocols', '-e frame.time_relative', 
                        '-e tcp.stream'  , '-e udp.stream'     , 
                        '-e ip.src'      , '-e tcp.srcport'    , '-e udp.srcport'        , 
                        '-e ip.dst'      , '-e tcp.dstport'    , '-e udp.dstport'        ,
                        '-e tcp.len'     , '-e udp.length'     ,
                        '-e tcp.seq'     , '-e tcp.nxtseq'     , 
                        '> ', outFile])
    os.system(command)

def mapUDPstream2csp(packetMeta, clientIP):
    streams = {}
    with open(packetMeta, 'r') as f:
        for l in f:
            l = l.strip().split('\t')
            if 'ip:udp' not in l[1]:
                continue
            else:
                streamNo = l[4]
                srcIP    = l[5]
                srcPort  = l[7]
                dstIP    = l[8]
                dstPort  = l[10]
                if srcIP != clientIP:
                    continue
                else:
                    csp = convert_ip(srcIP+'.'+srcPort) + '.' + convert_ip(dstIP+'.'+dstPort)
                    if csp in streams:
                        assert(streams[csp] == streamNo)
                    else:
                        streams[csp] = streamNo
    return streams

def extractStreams(pcap_file, follow_folder, client_ip, protocol, UDPstreamsMap=None):
    '''
    For every TCP/UDP flow, it makes a separate text file with hex payloads.
    
    The "-2 -R not tcp.analysis.retransmission" seems NOT to work with 
    '''
    protocol = protocol.lower()
    
    noRetransmitPcap = pcap_file.rpartition('.')[0]+'_no_retransmits.pcap'
    command          = 'tshark -2 -R "not tcp.analysis.retransmission" -r {} -w {}'.format(pcap_file, noRetransmitPcap)
    os.system(command)
    
    if protocol == 'tcp':
        command = ("PCAP_FILE='" + pcap_file + "'\n" +
                   "PCAP_FILE_noRe='" + noRetransmitPcap + "'\n" +
                   "follow_folder='" + follow_folder + "'\n" +
                   "END=$(tshark -r $PCAP_FILE_noRe -T fields -e " + protocol + ".stream | sort -n | tail -1)\n" +
                   "echo '\tNumber of streams: '$END+1\n\n" +
                   "for ((i=0;i<=END;i++))\n" +
                   "do\n" +
                    "\techo '\tDoing TCP stream: '$i\n" +
                    "\ttshark -r $PCAP_FILE_noRe -qz follow," + protocol + ",raw,$i > $follow_folder/follow-stream-$i.txt\n" +
                   "done"
                  )
        os.system(command)
        
    elif protocol == 'udp':
        streams = getUDPstreamsMap(pcap_file, client_ip)
        for s in streams:
            csp = convert_ip(s.replace(':', '.').split(',')[0]) + '.' + convert_ip(s.replace(':', '.').split(',')[1])
            if isLocal(csp[:15]) or  isLocal(csp[22:-6]):
                continue
            filename = UDPstreamsMap[csp]
            print '\tDoing UDP stream:', filename
            command = "tshark -r " + pcap_file + " -qz follow," + protocol + ",raw,"+ s + ' > ' + follow_folder + '/follow-stream-' + filename +'.txt'
            os.system(command)

def readPayload(streamFile):
    with open(streamFile, 'r') as f:
        for i in xrange(6):
            f.readline()
        
        l = f.readline()
        while l[0] != '=':
            if l[0] == '\t':
                yield ('s', l.strip())
            else:
                yield ('c', l.strip())
            l = f.readline()

def addUDPKeepAlives(udpClientQ):
    new_clientQ    = []
    prev_times     = {}
    prev_csp       = {}
    keepAliveCount = 0
    
    maxGap = 20
    step = maxGap/2
     
    for udp in udpClientQ:
         
        new_clientQ.append(udp)
         
        server_port = udp.c_s_pair[-5:]
         
        if server_port not in prev_times:
            prev_times[server_port] = udp.timestamp
            prev_csp[server_port]   = udp.c_s_pair
         
        else:
            diff = udp.timestamp - prev_times[server_port]
     
            if diff < maxGap:
                pass
     
            else:
                number = int(diff/step)
      
                for i in range(1, number+1):
                    new_udp = UDPset('', prev_times[server_port]+(i*step), prev_csp[server_port])
                    new_clientQ.append(new_udp)
                    keepAliveCount += 1
            
            prev_times[server_port] = udp.timestamp
            prev_csp[server_port]   = udp.c_s_pair
            
    new_clientQ.sort(key=lambda x: x.timestamp)
     
    PRINT_ACTION('Number of keep-alive packets added: '+str(keepAliveCount), 1, action=False)
    
    return new_clientQ

def createHashLUT(clientQ, replay_name, numberOfHashed=5):
    LUT     = {}
    seenCSP = {}
            
    for udp in clientQ:
        
        if udp.c_s_pair not in seenCSP:
            seenCSP[udp.c_s_pair] = 0
            
        if seenCSP[udp.c_s_pair] < numberOfHashed:
            the_hash = hash(udp.payload.decode('hex'))
            
            if the_hash in LUT:
                print 'PLEASE INVESTIGATE MANUALLY: DUP!:', udp.c_s_pair

            LUT[the_hash] = (replay_name, udp.c_s_pair)
            seenCSP[udp.c_s_pair] += 1
        
        else:
            continue
    
    return LUT

def sortAndClean(tcpMetas):
    #Sorting
    for stream in tcpMetas:
        for talker in tcpMetas[stream]:
            tcpMetas[stream][talker].sort(key=lambda x: [x.seq, x.timestamp])
    
    #Tossing retransmissions
    new_tcpMetas = {}
    for stream in tcpMetas:
        new_tcpMetas[stream] = {'c':[], 's':[]}
        for talker in tcpMetas[stream]:
            for x in tcpMetas[stream][talker]:
                try:
                    lastOne = new_tcpMetas[stream][talker][-1]
                except IndexError:
                    new_tcpMetas[stream][talker].append(x)
                    continue
                if x.seq != lastOne.seq:
                    new_tcpMetas[stream][talker].append(x)
                elif x.seq == lastOne.seq:
                    '''
                    There are cases where retransmitted packet partially overlaps with previous packet.
                    This clause is to take care of that
                    ''' 
                    if x.NXseq == lastOne.NXseq:
                        continue
                    else:
                        new_x = copy.deepcopy(x)
                        new_x.length =  x.length - lastOne.length
                        new_tcpMetas[stream][talker].append(new_x)
    return new_tcpMetas

def random_hex_bu(size):
    '''
    Takes the size of the random hex string it should generate:
        1-Generates a random string (chars and numbers) of size/2
        2-Encodes the generated randon string into hex
        
    Note: one ascii char will have length of 2 when converted to hex
    '''
    assert( size % 2 == 0)
    size = size/2
    asciiPayload = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(size))
    return asciiPayload.encode('hex')

def random_ascii_by_size(size):
    return ''.join(random.choice(string.ascii_letters + string.digits) for x in range(size))
    
def random_hex_by_size(size):
    '''
    Takes the size of the random hex string it should generate:
        1-Generates a random string (chars and numbers) of size/2
        2-Encodes the generated randon string into hex
        
    Note: one ascii char will have length of 2 when converted to hex
    '''
    assert( size % 2 == 0)
    size = size/2
    asciiPayload = random_ascii_by_size(size)
    return asciiPayload.encode('hex')

def random_hex_by_payload(hexPayload):
    '''
    Takes the size of the random hex string it should generate:
        1-Generates a random string (chars and numbers) of size/2
        2-Encodes the generated randon string into hex
        
    Note: one ascii char will have length of 2 when converted to hex
    '''
    if Configs().get('pureRandom'):
        return random_hex_by_size( len(hexPayload) )

    else:
        payload = hexPayload.decode('hex')
        
        if payload.startswith('GET'):
            req = Request( payload ).createRequestPacket()
            return req.encode('hex')
        
        elif payload.startswith('HTTP'):
            res = Response( payload ).createResponsePacket()
            return res.encode('hex')
        
        else:
            return random_hex_by_size( len(hexPayload) )
        
class Request(object):
    def __init__(self, stringData, splitter='\r\n'):
        (req, dummy, head)                        = stringData.partition(splitter)  
        (self.method, path_params, self.protocol) = req.split(' ')
        (self.path, dummy, params)                = path_params.partition('?')
        self.params                               = re.findall(r"(?P<name>.*?)=(?P<value>.*?)&"  , params+'&')        
        self.headers                              = re.findall(r"(?P<name>.*?): (?P<value>.*?){}".format(splitter), head)
        
    def createRequestPacket(self):
        serializedParams  = '&'.join([k[0] + '=' + random_ascii_by_size(len(k[1]))  for k in self.params])
        serializedHeaders = '\r\n'.join([k[0] + ': '+ random_ascii_by_size(len(k[1])) for k in self.headers])
        
        newRequest = (self.method + ' ' + 
                      random_ascii_by_size(len(self.path)) + 
                      '?' + serializedParams + ' ' + 
                      self.protocol + '\r\n' + 
                      serializedHeaders + '\r\n' + '\r\n')
         
        return newRequest
    
    def __str__(self):
        return str(self.headers)
    
class Response(object):
    def __init__(self, stringData, reqPath=None, splitter='\r\n'):
        self.reqPath               = reqPath
        (self.status, dummy, head) = stringData.partition(splitter)
        self.headers               = re.findall(r"(?P<name>.*?): (?P<value>.*?){}".format(splitter), head)
 
    def createResponsePacket(self):
        return "{}\r\n{}\r\n\r\n".format(self.status, '\r\n'.join([k[0]+': '+random_ascii_by_size(len(k[1])) for k in self.headers]))
    
    def __str__(self):
        return str(self.headers)

def tcpStream2Qs(streamMeta, streamHandle):
    '''
    Creates client and server queues from a tcp strams
    
    Flow diagram of this is in a Evernote note
    '''
    end     = True    
    
    clientQ = []
    serverQ = []
    
    packetReader = readNextPacket(streamMeta, streamHandle, randomPayload=Configs().get('randomPayload'))
    
    p = packetReader.next()
    
    #If the stream file is empty, the generator return the 
    #counter (which is a dict) at the very first .next() 
    if type(p) is dict: 
        end = False
    
    #The stream MUST start with a client request
    assert(p.talking == 'c')
    
    while end:
        
        reqList = [p]
        
        while end:
            pp      = p
            p       = packetReader.next()
            
            #If the stream file reaches the end, the  
            #generator return the counter (which is a dict) 
            if type(p) is dict: 
                end = False
                break
            
            if p.talking == 'c':
                clientQ.append( RequestSet(pp.payload, pp.csp, None, pp.timestamp) )
                reqList.append(p)
            else:
                break
        
        if not end:
            break 
        
        resTimeOrigin = p.timestamp
        resList       = [OneResponse(p.payload , 0)]
        pp = p
        
        while end:
            p = packetReader.next()
            if type(p) is dict: end = False; break
            
            if p.talking == 's':
                resList.append( OneResponse(p.payload , p.timestamp-resTimeOrigin) )
                pp = p
            else:
                tmpp = reqList[-1]
                serverQ.append( ResponseSet(''.join([x.payload for x in reqList]), resList) )
                clientQ.append( RequestSet(tmpp.payload, tmpp.csp, ''.join([x.payload for x in resList]), tmpp.timestamp) )
                break
    
    if pp.talking == 's':
        tmpp = reqList[-1]
        clientQ.append( RequestSet(tmpp.payload, tmpp.csp, ''.join([x.payload for x in resList]), tmpp.timestamp) )
        serverQ.append( ResponseSet(''.join([x.payload for x in reqList]), resList) )
    elif pp.talking == 'c':
        clientQ.append( RequestSet(pp.payload, pp.csp, None, pp.timestamp) )
        serverQ.append( ResponseSet(''.join([x.payload for x in reqList]), []) )
    
    '''
    Sometimes the order of packets mismatches the TCP stream.
    In these cases we need to adjust the times to avoid packets being
    send in the wrong order which results in tcp server/client halting 
    (because of length mismatch)
    '''
    for i in range(1, len(clientQ)):
        if clientQ[i].timestamp < clientQ[i-1].timestamp:
            clientQ[i].timestamp = clientQ[i-1].timestamp

    return clientQ, serverQ, pp.csp
    
def readNextPacket(streamMeta, streamHandle, randomPayload=False):
    counter = {'c':0, 's':0}
    
    while True:
        try:
            [talking, payload]  = streamHandle.next()
            p                   = streamMeta[talking][counter[talking]]
            
            if p.length != len(payload)/2:
                if '6279746573206d697373696e6720696e20636170747572652066696c655d' in payload:
                    continue
                else:
                    print '\nSomething is wrong!'
                    print '\nI am seeing payload in stream which is missing from packetMeta'
                    if DEBUG == 3: print p.timestamp, '\t', p.talking, '=', talking, '\t', p.protocol, '\t', p.stream, '\t', p.length, '=', len(payload)/2,'\t', payload
                    sys.exit(-1)
        except StopIteration:
            yield counter
            break
        
        counter[talking] += 1

        p.payload = payload
        
        if randomPayload is True:
#             p.payload = random_hex(len(p.payload))
            p.payload = random_hex_by_payload(p.payload)
        
        yield p
    
class singlePacket(object):
    def __init__(self, desString, clientIP):
        l              = desString.replace('\n', '').split('\t')
        self.timestamp = float(l[2])
        self.srcIP     = l[5]
        self.dstIP     = l[8]
        self.payload   = None
        self.talking   = None
        self.stream    = None
        
        if 'ip:tcp' in l[1]:
            self.protocol  = 'tcp'
        elif 'ip:udp' in l[1]:
            self.protocol  = 'udp'
        else:
            PRINT_ACTION('Skipping protocol: '+l[1], 1, action=False)
            return
                
        if self.protocol == 'tcp':
            self.stream  = l[3]
            self.srcPort = l[6]
            self.dstPort = l[9]
            self.length  = int(l[11])
            self.seq     = int(l[13])
            try:
                self.NXseq = int(l[14])
            except ValueError:
                self.NXseq = -1
                
        elif self.protocol == 'udp':
            self.stream  = l[4]
            self.srcPort = l[7]
            self.dstPort = l[10]
            self.length  = int(l[12])-8   #subtracting UDP header length
            
        if self.srcIP == clientIP:
            self.talking    = 'c'
            self.clientPort = self.srcPort.zfill(5)
            self.serverIP   = convert_ip(self.dstIP)
            self.serverPort = self.dstPort
            self.csp        = convert_ip(self.srcIP+'.'+str(self.srcPort)) + '-' + convert_ip(self.dstIP+'.'+str(self.dstPort))
        elif self.dstIP == clientIP:
            self.talking    = 's'
            self.clientPort = self.dstPort.zfill(5)
            self.serverIP   = convert_ip(self.srcIP)
            self.serverPort = self.srcPort
            self.csp        = convert_ip(self.dstIP+'.'+str(self.dstPort)) + '-' + convert_ip(self.srcIP+'.'+str(self.srcPort))

def isLocal(ip):
    ip = ip.split('.')

    if ip[0] == '10':
        return True
    if ip[0] == '172' and 16<=int(ip[1])<=31:
        return True
    if ip[0]+'.'+ip[1] == '192.168':
        return True
    else:
        return False
    
def run(*args):
    '''##########################################################'''
    PRINT_ACTION('Reading configs and args', 0)
    configs = Configs()
    configs.set('randomPayload', False)
    configs.set('pureRandom'   , False)
    configs.read_args(sys.argv)
    
    configs.check_for(['pcap_folder'])
    configs.show_all()
    configs.set('pcap_folder', os.path.abspath(configs.get('pcap_folder')))
    
    
    '''##########################################################'''
    PRINT_ACTION('Locating necessary files', 0)
    for file in os.listdir(configs.get('pcap_folder')):
        if file.endswith('.pcap'):
            if file.endswith('_no_retransmits.pcap'):
                continue
            pcap_file   = os.path.abspath(configs.get('pcap_folder')) + '/' + file
            replay_name = file.partition('.pcap')[0]
        if file == 'client_ip.txt':
            client_ip_file = os.path.abspath(configs.get('pcap_folder')) + '/' + file
    
    follow_folder_TCP = configs.get('pcap_folder') + '/' + os.path.basename(configs.get('pcap_folder')) + '_follows_TCP'
    follow_folder_UDP = configs.get('pcap_folder') + '/' + os.path.basename(configs.get('pcap_folder')) + '_follows_UDP'
    packetMeta        = os.path.abspath(configs.get('pcap_folder')) + '/' + 'packetMeta'

    if configs.is_given('replay_name'):
        replay_name = configs.get('replay_name')
    replay_name = replay_name.replace('_', '-')
    PRINT_ACTION('Replay name: '+replay_name, 0)
    
    if not os.path.isfile(pcap_file):
        PRINT_ACTION('The folder is missing the pcap file! Exiting with error!', 1, action=False, exit=True)
    
    if not os.path.isfile(client_ip_file):
        PRINT_ACTION('The folder is missing the client_ip file! Exiting with error!', 1, action=False, exit=True)
    else:
        PRINT_ACTION('Reading client_ip', 0)
        client_ip = read_client_ip(client_ip_file)
    
    '''##########################################################'''
    PRINT_ACTION('Extracting payloads and streams', 0)
    
    if not os.path.isfile(packetMeta):
        PRINT_ACTION('Creating packetMeta', 0)
        createPacketMeta(pcap_file, packetMeta)
    
    if not os.path.isdir(follow_folder_TCP):
        PRINT_ACTION('TCP Follows folder does not exist. Creating the follows folder...', 0)
        os.makedirs(follow_folder_TCP)
        extractStreams(pcap_file, follow_folder_TCP, client_ip, 'TCP')
    
    if not os.path.isdir(follow_folder_UDP):
        PRINT_ACTION('UDP Follows folder does not exist. Creating the follows folder...', 0)
        os.makedirs(follow_folder_UDP)
        UDPstreamsMap = mapUDPstream2csp(packetMeta, client_ip)
        extractStreams(pcap_file, follow_folder_UDP, client_ip, 'UDP', UDPstreamsMap=UDPstreamsMap)
    
    
    '''##########################################################'''
    handles = {'tcp':{}, 'udp':{}}
    for file in os.listdir(follow_folder_TCP):
        stream = file.rpartition('-')[2].partition('.')[0]
        handles['tcp'][stream] = readPayload(follow_folder_TCP+'/'+file)
    for file in os.listdir(follow_folder_UDP):
        stream = file.rpartition('-')[2].partition('.')[0]
        handles['udp'][stream] = readPayload(follow_folder_UDP+'/'+file)
    
    udpClientQ        = []
    serverQ           = {'tcp':{}, 'udp':{}}
    serversTimeOrigin = {'tcp':{}, 'udp':{}}
    LUT               = {'tcp':{}, 'udp':{}}
    startedStreams    = {'tcp':[], 'udp':[]}
    brokenStreams     = {'tcp':[], 'udp':[]}
    
    udpClientPorts    = set()
    udpServers        = {}
    tcpMetas          = {}
    
    with open(packetMeta, 'r') as f:
        for line in f:
            #0-Create packet object
            dPacket = singlePacket(line, client_ip)
            
            #1-Do necessary checks and skip when necessary
                        
            #1b-Skip no-man's packets or unknown protocols
            if (dPacket.talking is None) or (dPacket.stream is None):
                continue
            
            #1a-Skip local flows (mostly happens for DNS)
            if ((dPacket.talking == 'c' and isLocal(dPacket.dstIP)) or 
                (dPacket.talking == 's' and isLocal(dPacket.srcIP))   ):
                continue
            
            #1c-Skip no-payload packets
            if dPacket.length == 0:
                continue

            #1d-Skip streams where server is starting them!
            if dPacket.stream in brokenStreams[dPacket.protocol]:
                continue
            elif dPacket.stream not in startedStreams[dPacket.protocol]:
                if dPacket.talking == 's':
                    brokenStreams[dPacket.protocol].append(dPacket.stream)
                    continue
                else:
                    startedStreams[dPacket.protocol].append(dPacket.stream)
            
            #2a-For TCP, append to tcpMetas
            if dPacket.protocol == 'tcp':
                if dPacket.NXseq == -1:
                    continue
                elif dPacket.stream not in tcpMetas:
                    tcpMetas[dPacket.stream] = {'c':[], 's':[]}
                tcpMetas[dPacket.stream][dPacket.talking].append(dPacket)
                continue
                    
            #2b-For UDP, check consistency
            #Note we check len(payload)/2 because payload is in HEX
            (talking, payload) = handles[dPacket.protocol][dPacket.stream].next()
            assert(talking == dPacket.talking and len(payload)/2 == dPacket.length)
            
            #3-Extract necessary info
            udpClientPorts.add(dPacket.clientPort)
            
            if dPacket.serverIP not in udpServers:
                udpServers[dPacket.serverIP] = set()
            udpServers[dPacket.serverIP].add(dPacket.serverPort)
            
            #4-Add to queues
            if dPacket.csp not in serverQ[dPacket.protocol]:
                serverQ[dPacket.protocol][dPacket.csp]           = []
                serversTimeOrigin[dPacket.protocol][dPacket.csp] = dPacket.timestamp
            
            if configs.get('randomPayload') is True:
#                 payload = random_hex(len(payload))
                  payload = random_hex_by_payload(payload)
            
            if talking == 'c':
                udpClientQ.append( UDPset(payload, dPacket.timestamp, dPacket.csp) )
            elif talking == 's':
                serverQ[dPacket.protocol][dPacket.csp].append( UDPset(payload, dPacket.timestamp-serversTimeOrigin[dPacket.protocol][dPacket.csp], dPacket.csp) )
    
    PRINT_ACTION('Adding UDP keep-alive packets', 0)
    udpClientQ = addUDPKeepAlives(udpClientQ)
    
    PRINT_ACTION('Creating the hash Look-up Table', 0)
    LUT['udp'] = createHashLUT(udpClientQ, replay_name)

    PRINT_ACTION('Sorting tcpMetas and tossing retransmissions', 0)
    tcpMetas = sortAndClean(tcpMetas)
    
    PRINT_ACTION('Creating TCP queues', 0)
    
    sample_size    = 400
    tcpClientQ     = []
    tcpCSPs        = set()
    tcpServerPorts = set()
    
    diss   = []
    getLUT = {}
    
    streamIgnoreList = []   #example: streamIgnoreList = ['0', '1']
    
    for stream in sorted(tcpMetas.keys()):
        if DEBUG == 2: print '\tDoing stream:', stream, len(tcpMetas[stream]['c']), len(tcpMetas[stream]['s'])
        
        if stream in streamIgnoreList:
            print '\t\tStream in ignore list, skipping'
            continue
        
        [TMPclientQ, TMPserverQ, csp] = tcpStream2Qs(tcpMetas[stream], handles['tcp'][stream])


        '''
        ###############################
        Applying filters on TCP streams:
        ###############################
        '''
        #1- IP based filtering
        serverIP = csp[22:37]
        
        if serverIP in ipIgnoreList:
            print '\t\tIgnoring stream {}. Server IP in ignore list!'.format(csp)
            continue
        
        #2- Request based filtering
        if 'Host: static.ess.apple.com:80' in TMPclientQ[0].payload.decode('hex'):
            print '\t\tIgnoring stream {}. apple static!'.format(csp)
            continue
        '''
        ###############################
        '''

        toHash  = TMPclientQ[0].payload.decode('hex')[:sample_size]
        theHash = hash(toHash)
        
        if theHash in LUT['tcp']:
            print '\n\t*******************************************'
            print '\t*******************************************'
            print '\tATTENTION: take a look!!!'
            print '\tDUP in tcp LUT:', theHash, '\t', (replay_name, csp), '\n'
            print '\t', toHash
            print '\tSKIPPING!!!'
            print '\t*******************************************'
            print '\t*******************************************\n'  
            continue
        
        serverQ['tcp'][csp] = TMPserverQ
        tcpClientQ         += TMPclientQ
        
        tcpCSPs.add(csp)
        tcpServerPorts.add(csp[-5:])

        LUT['tcp'][theHash] = (replay_name, csp)
        
        '''
        ISPs may add/remove/modify HTTP headers. To prevent this from causing KeyErrors on the server
        when consulting the LUT, I create a getLUT[(replay_name, c_s_pair)] = dict(get request)
        
        When server sees a hash miss of a get request, consults getLUT and picks the closest. 
        '''
        if toHash[0:3] == 'GET':
            theDict = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", toHash.partition('\n')[2]))
            theDict['GET'] = toHash.partition('\r\n')[0]
            getLUT[(replay_name, csp)] = theDict
            diss.append( theDict )
    
    tcpClientQ.sort(key=lambda q: q.timestamp)
    
    PRINT_ACTION('Merging UDP and TCP', 0)
    clientQ = tcpClientQ + udpClientQ
    clientQ.sort(key=lambda q: q.timestamp)
        
    PRINT_ACTION('Serializing queues', 0)
    udpClientPorts = list(udpClientPorts) #JSON cannot serialize sets.
    tcpServerPorts = list(tcpServerPorts)
    for serverIP in udpServers:
        udpServers[serverIP] = list(udpServers[serverIP])
    
    PRINT_ACTION('Serializing TCP', 1, action=False)
    pickle.dump((tcpClientQ, list(tcpCSPs) , replay_name)                , open((pcap_file+'_client_tcp.pickle'), "w" ), 2)
    pickle.dump((serverQ['tcp'], tcpServerPorts, replay_name, LUT['tcp']), open((pcap_file+'_server_tcp.pickle'), "w" ), 2)
    json.dump((tcpClientQ, list(tcpCSPs)   , replay_name)                , open((pcap_file+'_client_tcp.json'), "w") , cls=TCP_UDPjsonEncoder)
     
    PRINT_ACTION('Serializing UDP', 1, action=False)
    pickle.dump((udpClientQ, udpClientPorts, {}, replay_name)        , open((pcap_file+'_client_udp.pickle'), "w" ), 2)
    pickle.dump((serverQ['udp'], LUT['udp'], udpServers, replay_name), open((pcap_file+'_server_udp.pickle'), "w" ), 2)
    json.dump((udpClientQ, udpClientPorts, {}, replay_name)          , open((pcap_file+'_client_udp.json'), "w"), cls=TCP_UDPjsonEncoder)
    
    PRINT_ACTION('Serializing all', 1, action=False)
    pickle.dump((clientQ, udpClientPorts, list(tcpCSPs), replay_name)          , open((pcap_file+'_client_all.pickle'), "w" ), 2)
    pickle.dump((serverQ, LUT, getLUT, udpServers, tcpServerPorts, replay_name), open((pcap_file+'_server_all.pickle'), "w" ), 2)
    json.dump((clientQ, udpClientPorts, list(tcpCSPs), replay_name)            , open((pcap_file+'_client_all.json'), "w"), cls=TCP_UDPjsonEncoder)
    
    PRINT_ACTION('Stats:', 0, action=True)
    serverSideCount = {}
    for protocol in serverQ:
        serverSideCount[protocol] = 0
        for csp in serverQ[protocol]:
            serverSideCount[protocol] += len(serverQ[protocol][csp]) 
            
    
    print '\t#Client packets: {} (TCP: {}, UDP: {}) '.format(len(clientQ), len(tcpClientQ), len(udpClientQ))
    print '\t#Server packets: {} (TCP: {}, UDP: {}) '.format(serverSideCount['tcp']+serverSideCount['udp'], serverSideCount['tcp'], serverSideCount['udp'])
    print '\t#UDP client ports:', len(udpClientPorts)
    print '\t#TCP CSPs:        ', len(serverQ['tcp'])
    print '\t#UDP CSPs:        ', len(serverQ['udp'])
    print '\t#UDP servers:     ', len(udpServers)
    print '\t#TCP server ports:', len(list(tcpServerPorts))
    
def main():
    run(sys.argv)

if __name__=="__main__":
    main()
