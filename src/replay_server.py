'''
#######################################################################################################
#######################################################################################################

by: Arash Molavi Kakhki (arash@ccs.neu.edu)
    Northeastern University
    
Goal: server replay script

Usage:
    python replay_server.py --ConfigFile=configs_local.cfg 

Mandatory arguments:
    pcap_folder: This is the folder containing parsed files necessary for the replay

Optional arguments:
    original_ports: if true, uses same server ports as seen in the original pcap
                      default: False

Example:
    sudo python replay_server.py --VPNint=tun0 --NoVPNint=eth0 --pcap_folder=[] --resultsFolder=[]

To kill the server:  
    ps aux | grep "python udp_server.py" |  awk '{ print $2}' | xargs kill -9
#######################################################################################################
#######################################################################################################
'''

import gevent.monkey; gevent.monkey.patch_all()

import sys, time, numpy, pickle, atexit, re, json, socket, urllib2, random, base64, string
from python_lib import *
try:
    import db as DB
except:
    print '\n\nNO DATABASE AVAILABLE\n\n'
    DB = None
import subprocess
import gevent, gevent.pool, gevent.server, gevent.queue, gevent.select
from gevent.coros import RLock


DEBUG = 5

logger = logging.getLogger('replay_server')

class TestObject(object):
    def __init__(self, ip, realID, replayName, testID):
        self.ip         = ip
        self.replayName = replayName
        self.realID     = realID
        self.testID     = testID
        self.lastActive = time.time()
        self.allowedGap = 5 * 60
    
    def update(self, testID):
        LOG_ACTION(logger, 'UPDATING: {}, {}, {}'.format(self.realID, self.ip, self.replayName), indent=2, action=False)
        self.testID     = testID
        self.lastActive = time.time()
        
    def isAlive(self):
        if time.time() - self.lastActive < self.allowedGap:
            return True
        else:
            return False

    def __rep__(self):
        return '{}--{}--{}--{}'.format(self.ip, self.realID, self.replayName, self.testID)
        
class ClientObj(object):
    '''
    A simple object to store client's info
    '''
    def __init__(self, incomingTime, realID, id, ip, replayName, testID, historyCount, extraString, connection):
        self.id               = id
        self.replayName       = replayName
        self.connection       = connection
        self.ip               = ip
        self.realID           = realID
        self.testID           = testID
        self.incomingTime     = incomingTime
        self.extraString      = extraString
        self.historyCount     = historyCount
        self.startTime        = time.time()
        self.ports            = set()
        self.hosts            = set()
        self.exceptions       = 'NoExp'
        self.success          = False  #it turns to True if replay finishes successfully
        self.secondarySuccess = False  #it turns to True if results and jitter info finish successfully
        self.iperfRate        = None
        self.mobileStats      = None
        self.clientTime       = None
        self.dumpName         = None
        self.targetFolder     = Configs().get('resultsFolder') + '/' + realID + '/'
        self.tcpdumpsFolder   = self.targetFolder + 'tcpdumpsResults/'
        self.jittersFolder    = self.targetFolder + 'jitterResults/'
        
        if not os.path.exists( self.targetFolder ):
            os.makedirs( self.targetFolder )
            os.makedirs( self.tcpdumpsFolder )
            os.makedirs( self.jittersFolder )
            
            xputsFolder = self.targetFolder + 'xputs/'
            os.makedirs( xputsFolder )
            
            plotsFolder = self.targetFolder + 'plots/'
            os.makedirs( plotsFolder )
            
            decisionsFolder = self.targetFolder + 'decisions/'
            os.makedirs( decisionsFolder )
    
    def setDump(self, dumpName):
        self.dumpName = dumpName
        
        if self.ip.startswith('10.101'):
            interface = Configs().get('VPNint')
        else:
            interface = Configs().get('NoVPNint')
            
        self.dump     = tcpdump(dump_name=dumpName, targetFolder=self.tcpdumpsFolder, interface=interface)
    
    def get_info(self):
        return map(str, [self.incomingTime, self.realID, self.id, self.ip, self.replayName, self.testID, self.extraString, self.historyCount, self.exceptions, self.success, self.secondarySuccess, self.iperfRate, time.time()-self.startTime, self.clientTime, self.mobileStats])

class TCPServer(object):
    def __init__(self, instance, Qs, greenlets_q, ports_q, errorlog_q, LUT, getLUT, sideChannel_all_clients, buff_size=4096, pool_size=10000, hashSampleSize=400, timing=True):
        self.instance       = instance
        self.Qs             = Qs
        self.greenlets_q    = greenlets_q
        self.ports_q        = ports_q
        self.errorlog_q     = errorlog_q
        self.LUT            = LUT
        self.getLUT         = getLUT
        self.buff_size      = buff_size
        self.pool_size      = pool_size
        self.hashSampleSize = hashSampleSize
        self.all_clients    = sideChannel_all_clients
        self.timing         = timing
        
    def run(self):
        '''
        Simply creates and runs a server with a pool if handlers.
        Note if original_ports is False, instance port is zero, so the OS picks a random free port
        '''
        pool   = gevent.pool.Pool(self.pool_size)
        server = gevent.server.StreamServer(self.instance, self.handle, spawn=pool)
        server.init_socket()
        #This option is important to make sure packets are not merged.
        #This can happen in NOVPN tests where MTU is bigger than packets 
        #(because record happened over VPN)
        server.socket.setsockopt(socket.SOL_TCP    , socket.TCP_NODELAY, 1)
        server.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        server.start()
        self.instance = (self.instance[0], server.address[1])
    
    def handleCertRequest(self, connection):
        r    = random.randint(2,200)
        name = "replayCertPass_" + str(r)
        
        fname         = "/opt/meddle/ClientCerts/%s.p12" % name
        data          = dict()
        data["alias"] = name

        with open(fname, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
        
        data["cert"] = encoded_string
        data["pass"] = "1234"
        
        print fname
        response = 'HTTP/1.1 200 OK\r\n\r\n' + json.dumps(data)
        connection.sendall( response )
    
    def handle(self, connection, address):
        '''
        Handles an incoming connection.
        
        Steps:
            0- Determine csp from hash LUT
                -if a sideChannel with the same id exists:
                    -if hash in LUT, done
                    -elif it's a GET request, consult getLUT (find closest get request)
                    -else, error!
                -else:
                    -if not a GET request, error
                    -elif "X-rr" exists, done.
                    -else, error!
            1- Put the handle greenlet on greenlets_q
            2- Reports the id and address on ports_q
            3- For every response set in Qs[replayName][csp]:
                a- receive expected request based on length (while loop)
                b- update buffer_len
                c- send response (for loop)
            4- Close connection
            
        IMPORTANT: if recv() returns an empty string --> the other side of the 
                   connection (client) is gone! and we just terminate the function 
                   (by calling return)
        '''
        clientIP   = address[0]
        clientPort = str(address[1]).zfill(5)
        
#         print 'newConn to {} from {}'.format(self.instance, address)
        
        #This is because we identify users by IP (for now)
        #So no two users behind the same NAT can run at the same time 
        id = clientIP
        
        #0- Determine csp from hash Lookup-Table (See above for details)
        new_data       = connection.recv( self.buff_size )
        
#         new_data = new_data.replace('akdjbwqeoihnqwrgn3qrion3jbefvlknqpvnijbvliqvboqbv;oqibviu3vboqibniurhbf;hqvoivbnq;eorbnorbnvoe;irwbvoqerb;oieqrbvoeiqrbvilequbr;iqjeriveqrovnero;ivnqeoibvneoirboierbno;erqibno;eibbf',
#                                     'o=AQE1Os28w8I_1z-RBFqynNMyy2nijvCHpMn__sItVKgE3T3ysmj5VGCHOZSr1wBA3Dk2a14PhhUuBRt2BoQJbZKh3IFQvNMAuENrH5zDX6Oz9Osf9JQEvIqr0Qexoh7t7o50&v=3&e=1417080434&t=blQ_gy241DnHI9TzTOIE861yNL4')
#         new_data = new_data.replace('129.10.11.12', '207.210.142.62')
#         new_data = new_data.replace('arashmolavijoon', 'googlevideo.com')
#         new_data = new_data.replace('    Host:hulu.com', 'video.xx.fbcdn.net', 1)
#         new_data = new_data.replace('x=', 'o=', 1)
#         new_data = new_data.replace('kakhkia', 'netflix')
        
        new_data_4hash = new_data[:self.hashSampleSize]
        
        if (new_data.startswith('GET /WHATSMYIPMAN')) or (new_data == 'WHATSMYIPMAN?'):
#             connection.sendall( clientIP )
            connection.sendall( "HTTP/1.1 200 OK\r\n\r\n{}".format(clientIP) )
            return
        
#         if '/getTempCertPassRandom' in new_data:
#             print 'Cert request came in'
#             soWhat = self.handleCertRequest(connection)
#             return
        
        if new_data[0:3] == 'GET':
            itsGET = True
        else:
            itsGET = False
        
        if id in self.all_clients:
            idExists = True
        else:
            idExists = False

        #This is for random replays where we add the info to the beginning of the first packet
        if new_data.strip().startswith('X-rr;'):
            info                  = new_data.partition(';X-rr')[0]
            [id, replayCode, csp] = info.strip().split(';')[1:4]
            replayName            = name2code(replayCode, 'code')
            exceptionsReport      = ''
            
        #If we know who the client is:
        elif idExists:
            try:
                (replayName, csp) = self.LUT['tcp'][hash(new_data_4hash)]
                exceptionsReport  = ''
            #The following exception handler is for dealing with header manipulations
            except KeyError:
                exceptionsReport = 'ContentModification'
                
                if itsGET:
                    
                    theDict = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", new_data.partition('\n')[2]))
                    theDict['GET'] = new_data.partition('\r\n')[0]
                    
                    try:
                        (replayName, csp) = getClosestCSP(self.getLUT, theDict)
                    except KeyError:
                        self.errorlog_q.put((id, 'Unknown GET', 'TCP', str(self.instance)))
                        return
        
                else:
                    self.errorlog_q.put((id, 'Unknown none-GET 1', 'TCP', str(self.instance)))
                    return
        
        #If we DON'T know who the client is: (possibly because of IP flipping)
        else:
            #This part is for adding info as a X- header for cases where an HTTP proxy
            #with different IP (from sideChannel) exists. 
            if itsGET:
                theDict = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", new_data.partition('\n')[2]))
                theDict['GET'] = new_data.partition('\r\n')[0]
                
                try:
                    [id, replayCode, csp] = theDict['X-rr'].strip().split(';')
                    replayName            = name2code(replayCode, 'code')
                    
                    exceptionsReport = 'ipFlip-resolved'
                except KeyError:
                    connection.sendall('WhoTheFAreU?'+';'+clientIP)
                    return
            else:
                connection.sendall('WhoTheFAreU?'+';'+clientIP)
                self.errorlog_q.put((id, 'Unknown none-GET 2', 'TCP', str(self.instance)))
                return

        try:
            dClient = self.all_clients[id][replayName]
            if exceptionsReport != '': dClient.exceptions = exceptionsReport
        except KeyError:
            self.errorlog_q.put((id, 'Unknown client', 'TCP', str(self.instance)))
            return
        
        #1- Put the handle greenlet on greenlets_q
        self.greenlets_q.put((gevent.getcurrent(), id, replayName, 'tcp', str(self.instance)))
        
        
        #2- Reports the id and address (both HOST and PORT) on ports_q
        self.ports_q.put(('host', id, replayName, clientIP))
        self.ports_q.put(('port', id, replayName, clientPort))
        
                
        #3- Handle request and response
        #if an X-rr header was added, do not consider it as expected bytes
        XrrHeader = new_data.partition('\r\nX-rr')[2].partition('\r\n')[0]
        if len(XrrHeader) > 0:
            extraBytes = len(XrrHeader) + 6     # 6 is for '\r\nX-rr'
        else:
            extraBytes = 0
        
#         print '\tfound csp:', csp
        
        buffer_len = len(new_data) - extraBytes

        
        for response_set in self.Qs[replayName][csp]:
            if itsGET is True:
                '''
                 Some ISPs add/remove/modify headers (e.g. Verizon adding perma-cookies).
                 This may result in the size of the GET request be different than what it's supposed
                 to be. To insure this will not break things, for GET request we read everything
                 that's in the buffer (instead of just reading the number of bytes that are expected)
                 And in case the GET request is spilling over multiple packets (really shouldn't be 
                 more than 2 !!!), we do a select and read remaining data in the buffer.
                 '''
                if buffer_len == 0:
                    new_data    = connection.recv( self.buff_size )
                    buffer_len += len( new_data )
                if buffer_len < response_set.request_len:
                    r, w, e = gevent.select.select([connection], [], [], timeout=0.01)
                    if r:
                        new_data = connection.recv( self.buff_size )
                        buffer_len += len( new_data )
            else:
                while buffer_len < response_set.request_len:
#                     print 'Waiting for: {} (csp: {})'.format(response_set.request_len-buffer_len, csp)
                    try:
                        new_data = connection.recv( min(self.buff_size, response_set.request_len-buffer_len) )
                    except:
                        return False
                    
                    if not new_data:
                        return False
                    
                    buffer_len += len(new_data)
            
#             connection.sendall(" ")
#             connection.sendall(" ")
            
            #Once the request is fully received, send the response
            
            randomizedCount = 0
            randomizedTshld = 1000000
            
            time_origin = time.time()
            for response in response_set.response_list:
                if self.timing is True:
                    gevent.sleep(seconds=((time_origin + response.timestamp) - time.time()))
                try:
                    
#                     if randomizedCount < randomizedTshld:
#                        randomizedCount += 1
#                        response.payload = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(len(response.payload)))
                    
#                     print response.payload

#                     response.payload = response.payload.replace("application/octet-stream", 
#                                                                 "ksjdgvfidsgfiuskdhfkisdd", 1)

#                     response.payload = response.payload.replace("Content-Type: video/mp4", 
#                                                                 "Content-Type: skdhfkisd", 1)

#                     response.payload = response.payload.replace("Content-Type: video/mp2t", 
#                                                                 "Content-Type: skdhfkisdd", 1)
#                     response.payload = response.payload.replace("Content-Type: video/MP2T", 
#                                                                 "Content-Type: skdhfkisdd", 1)
                    
#                     response.payload = str(response.payload).replace("flix", "kakh")
#                     response.payload = str(response.payload).replace("FLIX", "KAKH")
                    
#                     response.payload = str(response.payload).replace("Media Library",
#                                                                      "jsidgfiwuhgfe")
#                     response.payload = str(response.payload).replace("Video Media",
#                                                                      "jsidgfiwuhg")
#                     response.payload = response.payload.replace("application/octet-stream", 
#                                                                 "kakhkiation/arash-molavi")
#                     response.payload = response.payload.replace("Content-Range: bytes", 
#                                                                 "Arashoo-Kakhk: whats")
#                     response.payload = response.payload.replace("PiffStrm", 
#                                                                 "Arashoos")
#                     response.payload = response.payload.replace('X-Session-Info: addr=54.160.198.73;port=60761;argp=6.dGkeAWOk1bt3qCcblJ-iRqrk4yJ-5ZIwwTZnAprMzWI',
#                                                                 'ljhnfownofnwoi: fnoweifnowiefnowefnwekohwgbfiuwbfiuwebiuwbeibweviuwebvibwevibweviwbeviwebvibwviub')
#                     x = response.payload.partition('Netflix')
#                     connection.sendall(str(x[0]))
#                     connection.sendall(str(x[1]+x[2]))
                    connection.sendall(str(response.payload))
                except:
                    return False

#             if len(response_set.response_list) > 0:
#                 connection.sendall('AllDoneMF')

            buffer_len = 0
        
#         for response_set in self.Qs[replayName][csp]:
#             #First, receive the full request (receive expected number of bytes)
#             while buffer_len < response_set.request_len:
#                 print 'Waiting for:', response_set.request_len-buffer_len
#                 try:
#                     '''
#                     Some ISPs add/remove/modify headers (e.g. Verizon adding perma-cookies).
#                     This may result in the size of the GET request be larger than what it's supposed
#                     to be. To insure this will not break things, for GET request we read everything
#                     that's in the buffer (instead of just reading the number of bytes that are expected)
#                     NOTE: it's assuming the GET request is not bigger than self.buff_size = 4096
#                     '''
#                     if itsGET is True:
#                         new_data = connection.recv( self.buff_size )
#                     else:
#                         new_data = connection.recv( min(self.buff_size, response_set.request_len-buffer_len) )
#                 except:
#                     return False
#                 
#                 if not new_data:
#                     return False
#                 
#                 buffer_len += len(new_data)
#             
#             #Once the request is fully received, send the response
#             time_origin = time.time()
#             for response in response_set.response_list:
#                 if self.timing is True:
#                     gevent.sleep(seconds=((time_origin + response.timestamp) - time.time()))
#                 try:
#                     connection.sendall(str(response.payload))
#                 except:
#                     return False
# 
# #             if len(response_set.response_list) > 0:
# #                 connection.sendall('AllDoneMF')
# 
#             buffer_len = 0
        
        #4- Close connection
        connection.shutdown(gevent.socket.SHUT_RDWR)
        connection.close()
            
class UDPServer(object):
    '''
    self.mapping: this is the client mapping that server keeps to keep track what portion of the trace is
                  being replayed by each client IP and Port. These mappings are passed to SideChannel which
                  cleans them whenever client disconnects
    '''
    def __init__(self, instance, Qs, notify_q, greenlets_q, ports_q, errorlog_q, LUT, sideChannel_all_clients, buff_size=4096, pool_size=10000, timing=True):
        self.instance      = instance
        self.Qs            = Qs
        self.notify_q      = notify_q
        self.greenlets_q   = greenlets_q
        self.ports_q       = ports_q
        self.errorlog_q    = errorlog_q
        self.LUT           = LUT
        self.all_clients   = sideChannel_all_clients
        self.buff_size     = buff_size
        self.pool_size     = pool_size
        self.original_port = self.instance[1]
        self.mapping       = {}    #self.mapping[id][clientPort] = (id, serverPort, replayName)
        self.send_lock     = RLock()
        self.timing        = timing

    def run(self):
        
        pool = gevent.pool.Pool(self.pool_size)
        
        self.server = gevent.server.DatagramServer(self.instance, self.handle, spawn=pool)
        self.server.start()
            
        self.instance = (self.instance[0], self.server.address[1])
    
    def handle(self, data, client_address):
        '''
        Data is received from client_address:
            -if self.mapping[id][clientPort] exists --> client has already been identified:
                -if serverPort is None --> server has already started sending to this client, no need
                 for any action
                -else, set self.mapping[id][clientPort] = (None, None, None) and start sending
                 to client
            -else, the client is identifying, so react.
        '''
        clientIP   = client_address[0]
        clientPort = str(client_address[1]).zfill(5)
        
        #This is because we identify users by IP (for now)
        #So no two users behind the same NAT can run at the same time 
        id = clientIP
        
        try:
            self.mapping[id][clientPort]
            
        except KeyError:
            try:
                replayName, csp = self.LUT['udp'][hash(data)]
            except:
                self.errorlog_q.put((id, 'Unknown packet', 'UDP', str(self.instance)))
                return
            
            if id not in self.mapping:
                self.mapping[id] = {}
            self.mapping[id][clientPort] = 1
            self.ports_q.put(('port', id, replayName, clientPort))
                
            original_serverPort  = csp[-5:]
            original_clientPort  = csp[16:21]
            
            if Configs().get('original_ips'):
                gevent.Greenlet.spawn(self.send_Q, self.Qs[replayName][csp], time.time(), client_address, id, replayName)
            else:
                gevent.Greenlet.spawn(self.send_Q, self.Qs[replayName][original_serverPort][original_clientPort], time.time(), client_address, id, replayName)
    
    def send_Q(self, Q, time_origin, client_address, id, replayName):
        '''
        Sends a queue of UDP packets to client socket
        '''
        #1-Register greenlet
        self.greenlets_q.put((gevent.getcurrent(), id, replayName, 'udp', str(self.instance)))
        clientPort = str(client_address[1]).zfill(5)
        
        #2-Let client know the start of new send_Q
        self.notify_q.put((id, replayName, clientPort, 'STARTED'))
        
        #3- Start sending
        for udp_set in Q:
            if self.timing is True:
                gevent.sleep((time_origin + udp_set.timestamp) - time.time())
            
            with self.send_lock:
                self.server.socket.sendto(udp_set.payload, client_address)
            
            if DEBUG == 2: print '\tsent:', udp_set.payload, 'to', client_address
            if DEBUG == 3: print '\tsent:', len(udp_set.payload), 'to', client_address
        
        #4-Let client know the end of send_Q
        self.notify_q.put((id, replayName, clientPort, 'DONE'))
        
class SideChannel(object):
    '''
    Responsible for all side communications between client and server
    
    self.notify_q    : passed from main, for communication between udpServers and SideChannel.
    self.greenlets_q : tcpServers, udpServers, and SideChannel put new greenlets
                       on it and SideChannel.add_greenlets() reads them.
    self.ports_q     : to communicate with SideChannel.portCollector().
    self.logger_q    : Used for logging. replay_logger() continually reads this queue and write to file.
                       tcpdumps() writes to this queue whenever it starts/stops tcpdump.
   
    self.greenlets_q : Used for managing greenlets. add_greenlets() continually reads this queue and adds
                       new greenlets to self.greenlets.
                       This queue is passed to tcpServers, udpServers, and SideChannel so they can all put
                       new greenlets on it.
    
    self.portCollector: Used for tcpdump. tcpdumps() continually reads this queue.
                       It is passed to tcpServers, udpServers, and SideChannel.
                       tcpServer and udpServer put new coming ports on this queue (used for cleaning pcaps)
                       SideChannel puts start and stop on this queue to tell when to start/stop tcpdump process
    '''
    def __init__(self, instance, udpSenderCounts, notify_q, greenlets_q, ports_q, logger_q, errorlog_q, buff_size=4096):
        self.instance        = instance
        self.udpSenderCounts = udpSenderCounts
        self.notify_q        = notify_q
        self.greenlets_q     = greenlets_q
        self.ports_q         = ports_q
        self.logger_q        = logger_q
        self.errorlog_q      = errorlog_q
        self.buff_size       = buff_size
        self.all_clients     = {}            #self.all_clients[id][replayName] = ClientObj
        self.all_side_conns  = {}            #self.all_side_conns[g] = (id, replayName)
        self.id2g            = {}            #self.id2g[realID]      = g
        self.greenlets       = {}
        self.sleep_time      = 5 * 60
        self.max_time        = 5 * 60
        self.admissionCtrl   = {}           #self.admissionCtrl[id][replayName] = testObj
        self.inProgress      = {}           #self.inProgress[realID] = (id, replayName)
        self.instanceID      = self.getEC2instanceID()
        if DB is None:
            self.db = None
        else:
            self.db = DB.DB()
        
    def run(self, server_mapping, mappings):
        '''
        SideChannel has the following methods that should be always running
        
            1- wait_for_connections: every time a new connection comes in, it dispatches a 
               thread with target=handle to take care of the connection.
            2- notify_clients: constantly gets jobs from a notify_q and notifies clients.
               This could be acknowledgment of new port (coming from UDPServer.run) or 
               notifying of a send_Q end.
        '''
        
        self.server_mapping_json   = json.dumps(server_mapping)
        self.mappings              = mappings      #[mapping, ...] where each mapping belongs to one UDPServer

        gevent.Greenlet.spawn(self.notify_clients)
        gevent.Greenlet.spawn(self.add_greenlets)
        gevent.Greenlet.spawn(self.greenlet_cleaner)
        gevent.Greenlet.spawn(self.replay_logger, Configs().get('replayLog'))
        gevent.Greenlet.spawn(self.error_logger , Configs().get('errorsLog'))
        gevent.Greenlet.spawn(self.portCollector)
        
        self.pool   = gevent.pool.Pool(10000)
        self.server = gevent.server.StreamServer(self.instance, self.handle, spawn=self.pool)
        self.server.serve_forever()

    def handle(self, connection, address):
        '''
        Steps:
            0-  Get basic info: g, clientIP, incomingTime
            1-  Receive replay info: realID and replayName (id;replayName)
            2-  Check permission (log and close if no permission granted)
            3a- Receive iperf result
            3b- Receive mobile stats
            4-  Start tcpdump
            5a- Send server mapping to client
            5b- Send senderCount to client
            6-  Receive done confirmation from client and set success to True
            7-  Receive jitter
            8-  Receive results request and send back results
            9-  Set secondarySuccess to True and close connection
        '''
        #0- Get basic info: g, clientIP, incomingTime
        g            = gevent.getcurrent()
        clientIP     = address[0]
        incomingTime = time.strftime('%Y-%b-%d-%H-%M-%S', time.gmtime())
        
        #1- Receive replay info: realID and replayName (id;replayName)
        data = self.receive_object(connection)
        if data is None: return
        
        data = data.split(';')
        try:
            [realID, testID, replayName, extraString, historyCount, endOfTest] = data
            if endOfTest.lower() == 'true':
                endOfTest = True
            else:
                endOfTest = False
        except ValueError:
            [realID, testID, replayName, extraString, historyCount] = data
            endOfTest = True
        
        if extraString == '':
            extraString = 'extraString'


        #2- Check the following:
        #        -if a sideChannel with same realID is pending, kill it!
        #        -if unknown replayName
        #        -if someone else with the same IP is replaying
        LOG_ACTION(logger, 'New client: ' + '\t'.join([clientIP, realID, replayName, testID, extraString, historyCount, str(endOfTest)]), indent=1, action=False, newLine=True)
        id      = clientIP
        dClient = ClientObj(incomingTime, realID, id, clientIP, replayName, testID, historyCount, extraString, connection)
        dClient.hosts.add(clientIP)
        
        #2a- if a sideChannel with same realID is pending, kill it!
        self.killIfNeeded(realID)
        
        #2b- if unknown replayName
        if replayName not in self.udpSenderCounts:
            LOG_ACTION(logger, '*** Unknown replay name: {} ({}) ***'.format(replayName, realID))
            send_result = self.send_object(connection, '0;1')
            dClient.exceptions = 'UnknownRelplayName'
            self.logger_q.put('\t'.join(dClient.get_info()))
            return

        #2c- check permission
        #    if testID in ['NOVPN_1', 'SINGLE']: it's a new test:
        #        -if another back2back is on file with the same realID: kill it!
        #        -if self.admissionCtrl[id][replayName] exists: another user (different realID) with the same id and replayName on file
        #            -if it is not alive: kill it!
        #            -else: no permission
        #        -else:
        #            -populate self.admissionCtrl and self.inProgress with new testObj
        #    else:
        #        -make the realID exists on file
        #        -update the test object
        if testID in ['NOVPN_1', 'SINGLE']:
            
            try:
                (old_id, old_replayName) = self.inProgress[realID]
                del self.admissionCtrl[old_id][old_replayName]
                del self.inProgress[realID]
                self.killIfNeeded(realID)
            except KeyError:
                pass
            
            try:
                testObj = self.admissionCtrl[id][replayName]
            except KeyError:
                testObj = None

            if testObj is not None:
                if not testObj.isAlive():
                    self.killIfNeeded(testObj.realID)
                    self.admissionCtrl[id][replayName] = TestObject(clientIP, realID, replayName, testID)
                    self.inProgress[realID]            = (id, replayName)
                    good2go                            = True
                else:
                    good2go = False
            else:
                good2go                 = True
                self.inProgress[realID] = (id, replayName)
                testObj                 = TestObject(clientIP, realID, replayName, testID)
                
                try:
                    self.admissionCtrl[id][replayName] = testObj
                except KeyError:
                    self.admissionCtrl[id]             = {}
                    self.admissionCtrl[id][replayName] = testObj
                        
        else:
            try:
                (old_id, old_replayName) = self.inProgress[realID]
                testObj                  = self.admissionCtrl[old_id][old_replayName]
                good2go                  = True
                testObj.update(testID)
            except KeyError:
                good2go = False
        
        if good2go:
            LOG_ACTION(logger, 'Yay! Permission granted: {} - {} - {}'.format(clientIP, realID, testID), indent=2, action=False)
            dClient.setDump('_'.join(['server', realID, clientIP, replayName, id, incomingTime, testID, extraString, historyCount]))
            try:
                self.all_clients[id][replayName] = dClient
            except KeyError:
                self.all_clients[id]             = {}
                self.all_clients[id][replayName] = dClient
            
            self.all_side_conns[g] = (id, replayName)
            self.id2g[realID]      = g
            
            g.link(self.side_channel_callback)
            self.greenlets_q.put((g, id, replayName, 'sc', None))
            
            LOG_ACTION(logger, 'Notifying user know about granted permission: {} - {} - {}'.format(clientIP, realID, testID), indent=2, action=False)
            send_result = self.send_object(connection, '1;'+clientIP)
            LOG_ACTION(logger, 'Done notifying user know about granted permission: {} - {} - {}'.format(clientIP, realID, testID), indent=2, action=False)
        else:
            try:
                testOnFile = self.admissionCtrl[id][replayName]
                LOG_ACTION(logger, '*** NoPermission. You: {} - {} - {}, OnFile: {} - {} - {} ***'.format(clientIP, realID, testID, testOnFile.ip, testOnFile.realID, testOnFile.testID))
            except KeyError:
                LOG_ACTION(logger, '*** NoPermission. You: {} - {} - {}, OnFile: None ***'.format(clientIP, realID, testID))
            send_result = self.send_object(connection, '0;2')
            dClient.exceptions = 'NoPermission'
            self.logger_q.put('\t'.join(dClient.get_info()))
            

        #3a- Receive iperf result
        data = self.receive_object(connection)
        if data is None: return
        
        data = data.split(';')
        
        if data[0] == 'WillSendIperf':
            LOG_ACTION(logger, 'Waiting for iperf result for: '+realID)
            iperfRate = self.receive_object(connection)
            if iperfRate is None: return
            dClient.iperfRate = iperfRate
            LOG_ACTION(logger, 'iperf result for {}: {}'.format(realID, iperfRate))
        elif data[0] == 'NoIperf':
            LOG_ACTION(logger, 'No iperf for: '+realID, indent=2, action=False)
        
        #3b- Receive mobile stats
        data = self.receive_object(connection)
        if data is None: return
        
        data = data.split(';')
        
        if data[0] == 'WillSendMobileStats':
            LOG_ACTION(logger, 'Waiting for mobile stats result for: '+realID, indent=2, action=False)
            mobileStats = self.receive_object(connection)
            if mobileStats is None: return
            dClient.mobileStats = mobileStats
            LOG_ACTION(logger, 'Mobile stats for {}: {}'.format(realID, mobileStats), indent=2, action=False)
        elif data[0] == 'NoMobileStats':
            LOG_ACTION(logger, 'No mobile stats for '+realID, indent=2, action=False)
        
        #4- Start tcpdump
        LOG_ACTION(logger, 'Starting tcpdump for: id: {}, historyCount: {}'.format(dClient.realID, dClient.historyCount), indent=2, action=False)
#        command = dClient.dump.start(host=dClient.ip)
        command = dClient.dump.start()
        LOG_ACTION(logger, 'tcpdump start command: id: {}, historyCount: {}: {}'.format(dClient.realID, dClient.historyCount, command), indent=2, action=False)
        
        
        #5a- Send server mapping to client
        send_result = self.send_object(connection, self.server_mapping_json)
        if send_result is False: return
        #5b- Send senderCount to client
        send_result = self.send_object(connection, str(self.udpSenderCounts[replayName]))
        if send_result is False: return
        
        
        #6- Receive done confirmation from client and set success to True
        data = self.receive_object(connection)
        if data is None: return
        
        data = data.split(';')
        if data[0] == 'DONE':
            pass
        elif data[0] == 'ipFlip':
            LOG_ACTION(logger, 'IP flipping detected: {}, {}'.format(dClient.realID, dClient.historyCount), indent=2, action=False)
            dClient.exceptions = 'ipFlip'
            return
        elif data[0] == 'timeout':
            LOG_ACTION(logger, 'Client enforeced timeout: {}, {}'.format(dClient.realID, dClient.historyCount), indent=2, action=False)
            dClient.exceptions = 'clientTimeout'
            return
        else:
            print '\nSomething weird happened! Unexpected command!\n'
            return
        
        dClient.success    = True
        dClient.clientTime = data[1]
        
        #7- Receive jitter
        data = self.receive_object(connection)
        if data is None: return
        
        data = data.split(';')
        if data[0] == 'WillSendClientJitter':
            if not self.get_jitter(connection, dClient.jittersFolder+'/jitter_sent_'+dClient.dumpName+'.txt'): return
            if not self.get_jitter(connection, dClient.jittersFolder+'/jitter_rcvd_'+dClient.dumpName+'.txt'): return

        elif data[0] == 'NoJitter':
            pass
        
        '''
        It is very important to send this confirmation. Otherwise client exits early and can
        cause permission issue when replaying back to back!
        '''
        if self.send_object(connection, 'OK') is False: return


        #8- Receive results request and send back results
        data = self.receive_object(connection)
        if data is None: return
  
        data = data.split(';')
          
        if data[0] != 'Result':
            print '\nSomething weird happened! Result\n'
            return
          
        if data[1] == 'Yes':
            if self.send_reults(connection) is False: return
        elif data[1] == 'No':
            if self.send_object(connection, 'OK') is False: return
        
        if endOfTest or (testID == 'SINGLE'):
            LOG_ACTION(logger, 'Cleaning inProgress and admissionCtrl for: '+realID, indent=2, action=False)
            (id, replayName) = self.inProgress[realID]
            del self.admissionCtrl[id][replayName]
            del self.inProgress[realID]
            
        #9- Set secondarySuccess to True and close connection
        dClient.secondarySuccess = True
        
        connection.shutdown(gevent.socket.SHUT_RDWR)
        connection.close()

    def getEC2instanceID(self):
        try:
            return urllib2.urlopen('http://169.254.169.254/latest/meta-data/instance-id').read()
        except:
            return None
    
    def killIfNeeded(self, realID):
        try:
            tmpG = self.id2g[realID]        
        except KeyError:
            tmpG = None
        
        if tmpG is not None:
            LOG_ACTION(logger, 'Have to kill previous idle sideChannel: '+realID, indent=2, action=False)
            tmpG.unlink(self.side_channel_callback)
            self.side_channel_callback(tmpG)
            tmpG.kill(block=True)
    
    def get_jitter(self, connection, outfile):
        jitters = self.receive_object(connection)
        if jitters is None:
            jitters = str(jitters)
        with open(outfile, 'wb') as f:
            f.write(jitters)
        return True

    def notify_clients(self):
        '''
        Whenever a udpServer is done sending to a client port, it puts on notify_q.
        This function continually reads notify_q and notifies clients.
        '''
        while True:
            data = self.notify_q.get()
            [id, replayName, port, command] = data
            
            if DEBUG == 2: print '\tNOTIFYING:', data, str(port).zfill(5)
            
            try:
                self.send_object(self.all_clients[id][replayName].connection, ';'.join([command, str(port).zfill(5)]) )
            except KeyError:
                print "SideChannel terminated. Can't notify:", id
                pass
    
    def send_object(self, connection, message, obj_size_len=10):
        try:
            connection.sendall(str(len(message)).zfill(obj_size_len))
            connection.sendall(message)
            return True
        except:
            return False
    
    def receive_object(self, connection, obj_size_len=10):
        object_size = self.receive_b_bytes(connection, obj_size_len)
        
        if object_size is None:
            return None

        try:
            object_size = int(object_size)
        except:
            return None
        
        obj = self.receive_b_bytes(connection, object_size)
        
        
        return obj
    
    def receive_b_bytes(self, connection, b):
        data = ''
        while len(data) < b:
            try:
                new_data = connection.recv( min(b-len(data), self.buff_size) )
            except:
                return None
            
            if not new_data:
                return None
            
            data += new_data
        
        return data
    
    def send_reults(self, connection):
        result_file = 'smile.jpg'
        f = open(result_file, 'rb')
        return self.send_object(connection, f.read())

    def side_channel_callback(self, *args):
        '''
        When a side_channel greenlet exits, this function is called and 
            1- Locate client object
            2- Stops tcpdump
            3- Clean pcap (if replay successful) 
            4- Asks to kill dnagling greenlets and clean greenlets dict (buy putting the request on greenlets.q queue)  
            5- Mapping is cleaned
            6- Clean dicts
        '''
        
        #Locate client object
        g                = args[0]
        (id, replayName) = self.all_side_conns[g]
        dClient          = self.all_clients[id][replayName]
        
        LOG_ACTION(logger, 'side_channel_callback for: {} ({}). Success: {}, Client time: {}, historyCount: {}'.format(dClient.realID, 
                                                                                                                       dClient.testID, 
                                                                                                                       dClient.success, 
                                                                                                                       dClient.clientTime,
                                                                                                                       dClient.historyCount,
                                                                                                                       ), indent=2, action=False)
        
        #Stop tcpdump
        LOG_ACTION(logger, 'Stopping tcpdump for: id: {}, historyCount: {}'.format(dClient.realID, dClient.historyCount), indent=2, action=False)
        tcpdumpResult = dClient.dump.stop()
        LOG_ACTION(logger, 'tcpdumpResult: {}'.format(tcpdumpResult), indent=3, action=False)
        try:
            self.logger_q.put( '\t'.join(dClient.get_info() + tcpdumpResult) )
        except:
            pass
        
        #Create _out.pcap (only if the replay was successful)
        if dClient.secondarySuccess:
            command = clean_pcap(dClient.dump.dump_name, dClient.ports, hostList=dClient.hosts)
            LOG_ACTION(logger, 'CleanPcap command: id: {}, historyCount: {}: {}'.format(dClient.realID, dClient.historyCount, command), indent=2, action=False)
        
        #schedule greenlet to be removed
        self.greenlets_q.put((None, id, replayName, 'remove', None))
        
        #Clean UDP mappings (populated in UDPserver.handle)
        for mapping in self.mappings:
            for port in dClient.ports:
                try:
                    del mapping[id][port]
                except KeyError:
                    pass
        
        #Clean dicts
        del self.all_clients[id][replayName]
        del self.all_side_conns[g]
        del self.id2g[ dClient.realID ]
        
        return True

    def replay_logger(self, replay_log):
        '''
        Logs all replay activities.
        '''
        replayLogger = logging.getLogger('replayLogger')
        createRotatingLog(replayLogger, replay_log)
        while True:
            toWrite = self.logger_q.get()
            replayLogger.info(toWrite)
            if self.db is not None:
                self.db.insertReplay(toWrite, self.instanceID)
            else:
                print 'No DB available!'
    
    def error_logger(self, error_log):
        '''
        Logs all errors and exceptions.
        '''
        
        errorLogger = logging.getLogger('errorLogger')
        createRotatingLog(errorLogger, error_log)
        
        while True:
            toWrite = self.errorlog_q.get()
            id      = toWrite[0]
            toWrite = str(toWrite)
            
            print '\n***CHECK ERROR LOGS: {}***'.format(toWrite)
            
#             try:
#                 self.all_clients[id].exceptions = 'WithExp'
#                 toWrite = '\t'.join(self.all_clients[id].get_info())
#             except:
#                 toWrite = id + '\tNoSuchClient'
            
            errorLogger.info( toWrite )
    
    def add_greenlets(self):
        '''
        Everytime a clinet connects to the SideChannel or a TCPServer, a greenlet is spawned.
        These greenlets are added to a dictionary with timestamp (using this function) and 
        are garbage collected periodically using greenlet_cleaner() 
        '''
        while True:
            (g, clientIP, replayName, who, instance) = self.greenlets_q.get()
            
            #SideChannel asking to add greenlet
            if who == 'sc':
                try:
                    self.greenlets[clientIP][replayName] = {g:time.time()}
                except KeyError:
                    self.greenlets[clientIP]             = {}
                    self.greenlets[clientIP][replayName] = {g:time.time()}
            
            #side_channel_callback asking to remove greenlet
            elif who == 'remove':
                LOG_ACTION(logger, 'Cleaning greenlets for: '+clientIP, action=False, indent=2)
                try:
                    for x in self.greenlets[clientIP][replayName]:
                        x.kill(block=False)
                    del self.greenlets[clientIP][replayName]
                except KeyError:
                    pass
                    
            #TCP/UDP servers asking to add greenlet
            else:
                try:
                    self.greenlets[clientIP][replayName][g] = time.time()
                except KeyError:
                    g.kill(block=False)
                    self.errorlog_q.put((clientIP, replayName, 'Unknown connection', who.upper(), instance))
                    
    def greenlet_cleaner(self):
        '''
        This goes through self.greenlets and kills any greenlet which is 
        self.max_time seconds or older
        '''
        while True:
            LOG_ACTION(logger, 'Cleaning dangling greenlets: {}'.format(len(self.greenlets)))
            for ip in self.greenlets:
                
                for replayName in self.greenlets[ip].keys():
                    
                    for g in self.greenlets[ip][replayName].keys():
                
                        if g.successful():
                            del self.greenlets[ip][replayName][g]
                        
                        elif time.time() - self.greenlets[ip][replayName][g] > self.max_time:
                            g.kill(block=False)
                            del self.greenlets[ip][replayName][g]
            
                    if len(self.greenlets[ip][replayName]) == 0:
                        del self.greenlets[ip][replayName]
            
            LOG_ACTION(logger, 'Done cleaning: {}'.format(len(self.greenlets)), indent=1, action=False)
            gevent.sleep(self.sleep_time)
            
    def portCollector(self):
        while True:
            (command, id, replayName, port_or_host) = self.ports_q.get()
            
            try:
                dClient = self.all_clients[id][replayName]
            except:
                LOG_ACTION(logger, 'portCollector cannot find client: '+data, level='EXCEPTION', doPrint=False)
                continue

            if command == 'port':
                dClient.ports.add( port_or_host )
            
            elif command == 'host':
                dClient.hosts.add( port_or_host )
                
def getDictDistance(headersDic1, headersDic2):
    distance = 0
    for k in headersDic1.keys():
        try:
            if headersDic1[k] == headersDic2[k]:
                distance -= 1
            else:
                distance += 1
        except:
            continue
    return distance

def getClosestCSP(getLUT, headersDict):
    minDistance = 10000
    #If there is only one with the same GET request, return that
    closestCSPs = []
    for csp in getLUT:
        if headersDict['GET'] == getLUT[csp]['GET']:
            closestCSPs.append(csp)
            
    if len(closestCSPs) == 1:
        return closestCSPs[0]

    #If more than one, now do edit distance on headers
    if len(closestCSPs) > 0:
        toTest = closestCSPs
    #If none, do edit distance on all
    else:
        toTest = getLUT.keys()
    
    closestCSP = None
    
    for csp in toTest:
        distance = getDictDistance(headersDict, getLUT[csp])
        if distance < minDistance:
            minDistance = distance
            closestCSP  = csp
    
    return closestCSP

def merge_servers(Q):

    newQ        = {}
    senderCount = 0
    
    for csp in Q:
        originalServerPort = csp[-5:]
        originalClientPort = csp[16:21]
        
        if originalServerPort not in newQ:
            newQ[originalServerPort] = {}
        
        if originalClientPort not in newQ[originalServerPort]:
            newQ[originalServerPort][originalClientPort] = []
            
        newQ[originalServerPort][originalClientPort] += Q[csp]
     
    for originalServerPort in newQ:
        for originalClientPort in newQ[originalServerPort]:
            newQ[originalServerPort][originalClientPort].sort(key=lambda x: x.timestamp)
            senderCount += 1
    
    return newQ, senderCount
        
def load_Qs(serialize='pickle'):
    '''
    This loads and de-serializes all necessary objects.
    
    NOTE: the parser encodes all packet payloads into hex before serializing them.
          So we need to decode them before starting the replay.
    '''
    Qs              = {'tcp':{}, 'udp':{}}
    folders         = []
    allUDPservers   = {}
    udpSenderCounts = {}
    LUT             = {}
    getLUT          = {}
    tcpPorts        = set()
    allIPs          = set()
    
    pcap_folder     = Configs().get('pcap_folder')
    
    if os.path.isfile(pcap_folder):
        with open(pcap_folder, 'r') as f:
            for l in f:
                folders.append(l.strip())
    else:
         folders.append(pcap_folder)
    
    for folder in folders:
        if folder == '':
            continue
        
        for file in os.listdir(folder):
            if file.endswith(('_server_all.' + serialize)):
                pickle_file = os.path.abspath(folder) + '/' + file
                break
        
        if serialize == 'pickle':
            Q, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName = pickle.load(open(pickle_file, 'r'))

        elif serialize == 'json':
            print '\n\nJSON NOT SUPPORTED YET!\n\n'
            sys.exit(-1)

        LOG_ACTION(logger, 'Loading for: ' + replayName, indent=1, action=False)

        #Decode all payloads
        for csp in Q['udp']:
            for p in Q['udp'][csp]:
                p.payload = p.payload.decode('hex')
        for csp in Q['tcp']:
            for response_set in Q['tcp'][csp]:
                for one_response in response_set.response_list:
                    one_response.payload = one_response.payload.decode('hex')

        Qs['tcp'][replayName] = Q['tcp']
        Qs['udp'][replayName] = Q['udp']
        
        LUT[replayName]    = tmpLUT
        getLUT[replayName] = tmpgetLUT
        
        #Calculating udpSenderCounts
        udpSenderCounts[replayName] = len(Q['udp'])

        #Adding to server list
        for serverIP in udpServers:
            if serverIP not in allUDPservers:
                allUDPservers[serverIP] = set()
            for serverPort in udpServers[serverIP]:
                allUDPservers[serverIP].add(serverPort)
        
        #Merging Q if original_ips is off
        if not Configs().get('original_ips'):
            Qs['udp'][replayName], udpSenderCounts[replayName] = merge_servers(Q['udp'])
            
        for port in tcpServerPorts:
            tcpPorts.add(port)
        
    #Creating tcpIPs
    tcpIPs  = {}
    for replayName in Qs['tcp']:
        for csp in Qs['tcp'][replayName]:
            sss  = csp.partition('-')[2]
            ip   = sss.rpartition('.')[0]
            port = sss.rpartition('.')[2]
            
            if ip not in tcpIPs:
                tcpIPs[ip] = set()
            tcpIPs[ip].add(port)
    
    for protocol in Qs:
        for replayName in Qs[protocol]:
            for csp in Qs[protocol][replayName]:
                allIPs.add(csp.partition('-')[2].rpartition('.')[0])
    
    
    finalLUT = {'tcp':{}, 'udp':{}}
    c = 0
    for replayName in LUT:
        for protocol in LUT[replayName]:
            for x in LUT[replayName][protocol]:
                c += 1
                try:
                    finalLUT[protocol][x]
                    print 'DUP in finalLUT', protocol, x, finalLUT[protocol][x], LUT[replayName][protocol][x]
                except:
                    pass
                finally:
                    finalLUT[protocol][x] = LUT[replayName][protocol][x]
                    
    print c, len(finalLUT['tcp'])+len(finalLUT['udp'])
    
    finalgetLUT = {}
    c = 0
    for replayName in getLUT:
        for csp in getLUT[replayName]:
            c += 1 
            try:
                finalgetLUT[csp]
                print 'DUP in finalgetLUT', csp
            except:
                pass
            finally:
                finalgetLUT[csp] = getLUT[replayName][csp]
                
    print c, len(finalgetLUT)
    
    return Qs, finalLUT, finalgetLUT, allUDPservers, udpSenderCounts, tcpIPs, tcpPorts, allIPs

def atExit(aliases, iperf):
    '''
    This function is called before the script terminates.
    It tears down all created network aliases.
    '''
    for alias in aliases:
        alias.down()
    
    iperf.terminate()
    
def run(*args):
    '''
    notify_q : Queue for udpServers and SideChannel communications
               udpServers put on it whenever they're done sending to a client port.
               SideChannel get from it and notifies clients that the port is done.
    
    server_mapping: Server mapping that's sent to client
    
    mappings:  Hold udpServers' client mapping and passed to SideChannel for cleaning
    '''
    
    PRINT_ACTION('Reading configs and args', 0)
    configs = Configs()
    configs.set('sidechannel_port', 55555)
    configs.set('serialize'       , 'pickle')
    configs.set('mainPath'        , '/data/RecordReplay/')
    configs.set('resultsFolder'   , 'ReplayDumps/')
    configs.set('logsPath'        , 'logs/')
    configs.set('replayLog'       , 'replayLog.log')
    configs.set('errorsLog'       , 'errorsLog.log')
    configs.set('serverLog'       , 'serverLog.log')
    configs.set('timing'          , True)
    configs.set('original_ports'  , True)
    configs.set('original_ips'    , False)
    configs.set('multiInterface'  , False)
    configs.set('iperf'           , False)
    configs.set('iperf_port'      , 5555)
    configs.read_args(sys.argv)
    configs.check_for(['pcap_folder', 'NoVPNint', 'VPNint'])
    
    if configs.get('multiInterface'):
        configs.check_for(['publicIP'])
    else:
        configs.set('publicIP', '')
                
    PRINT_ACTION('Configuring paths', 0)
    configs.set('resultsFolder' , configs.get('mainPath')+configs.get('resultsFolder'))
    configs.set('logsPath'      , configs.get('mainPath')+configs.get('logsPath'))
    configs.set('replayLog'     , configs.get('logsPath')+configs.get('replayLog'))
    configs.set('errorsLog'     , configs.get('logsPath')+configs.get('errorsLog'))
    configs.set('serverLog'     , configs.get('logsPath')+configs.get('serverLog'))

    PRINT_ACTION('Setting up directories', 0)
    if not os.path.isdir(configs.get('mainPath')):
        os.makedirs(configs.get('mainPath'))
    if not os.path.isdir(configs.get('logsPath')):
        os.makedirs(configs.get('logsPath'))

    createRotatingLog(logger, configs.get('serverLog'))
    
    configs.show_all()
    
    LOG_ACTION(logger, 'Starting replay server. Configs: '+str(configs), doPrint=False)
    
    LOG_ACTION(logger, 'Creating variables')
    notify_q       = gevent.queue.Queue()
    logger_q       = gevent.queue.Queue()
    errorlog_q     = gevent.queue.Queue()
    greenlets_q    = gevent.queue.Queue()
    ports_q        = gevent.queue.Queue()
    server_mapping = {'tcp':{}, 'udp':{}}
    mappings       = []

    LOG_ACTION(logger, 'Creating results folders')
    if not os.path.isdir(configs.get('resultsFolder')):
        os.makedirs(configs.get('resultsFolder'))
    
    if configs.get('iperf'):
        LOG_ACTION(logger, 'Starting iperf server')
        iperf = subprocess.Popen(['iperf', '-s'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        iperf = None
    
    LOG_ACTION(logger, 'Loading server queues')
    Qs, LUT, getLUT, udpServers, udpSenderCounts, tcpIPs, tcpPorts, allIPs = load_Qs(serialize=configs.get('serialize'))
    
    LOG_ACTION(logger, 'IP aliasing')
    alias_c = 1
    aliases = []
    if configs.get('original_ips'):
        for ip in sorted(allIPs):
            aliases.append(IPAlias(ip, configs.get('NoVPNint')+':'+str(alias_c)))
            alias_c += 1

    LOG_ACTION(logger, 'Passing aliases to atExit', indent=1, action=False)
    atexit.register(atExit, aliases=aliases, iperf=iperf)
    
    LOG_ACTION(logger, 'Creating and running the side channel')
    side_channel = SideChannel((configs.get('publicIP'), configs.get('sidechannel_port')), udpSenderCounts, notify_q, greenlets_q, ports_q, logger_q, errorlog_q)

    LOG_ACTION(logger, 'Creating and running UDP servers')
    ports_done = {}
    count      = 0
    for ip in sorted(udpServers.keys()):
        for port in udpServers[ip]:
            
            port = port.zfill(5)
            
            if configs.get('original_ports'):
                serverPort = int(port)
            else:
                serverPort = 0
            
            if configs.get('original_ips'):
                server = UDPServer((ip, serverPort), Qs['udp'], notify_q, greenlets_q, ports_q, errorlog_q, LUT, side_channel.all_clients, timing=configs.get('timing'))
                server.run()
                LOG_ACTION(logger, ' '.join([str(count), 'Created socket server for', str((ip, port)), '@', str(server.instance)]), level=logging.DEBUG, doPrint=False)
                mappings.append(server.mapping)
                count += 1
            elif port not in ports_done:
                server = UDPServer((configs.get('publicIP'), serverPort), Qs['udp'], notify_q, greenlets_q, ports_q, errorlog_q, LUT, side_channel.all_clients, timing=configs.get('timing'))
                server.run()
                ports_done[port] = server
                LOG_ACTION(logger, ' '.join([str(count), 'Created socket server for', str((ip, port)), '@', str(server.instance)]), level=logging.DEBUG, doPrint=False)
                mappings.append(server.mapping)
                count += 1
            else:
                server = ports_done[port]
            
            if ip not in server_mapping['udp']:
                server_mapping['udp'][ip] = {}
            server_mapping['udp'][ip][port] = server.instance
    LOG_ACTION(logger, 'Created {} UDP socket server'.format(count), indent=1, action=False)
    

    LOG_ACTION(logger, 'Creating and running TCP servers')
    ports_done = {}
    count      = 0
    for ip in sorted(tcpIPs.keys()):
        for port in tcpIPs[ip]:
            
            port = port.zfill(5)
            
            if configs.get('original_ports'):
                serverPort = int(port)
            else:
                serverPort = 0
                
            if configs.get('original_ips'):
                server = TCPServer((ip, serverPort), Qs['tcp'], greenlets_q, ports_q, errorlog_q, LUT, getLUT, side_channel.all_clients, timing=configs.get('timing'))
                server.run()
                LOG_ACTION(logger, ' '.join([str(count), 'Created socket server for', str((ip, port)), '@', str(server.instance)]), level=logging.DEBUG, doPrint=False)
                count += 1
            elif port not in ports_done:
                server = TCPServer((configs.get('publicIP'), serverPort), Qs['tcp'], greenlets_q, ports_q, errorlog_q, LUT, getLUT, side_channel.all_clients, timing=configs.get('timing'))
                server.run()
                ports_done[port] = server
                LOG_ACTION(logger, ' '.join([str(count), 'Created socket server for port', str((ip, port)), '@', str(server.instance)]), level=logging.DEBUG, doPrint=False)
                count += 1
            else:
                server = ports_done[port]
                 
            if ip not in server_mapping['tcp']:
                server_mapping['tcp'][ip] = {}
            server_mapping['tcp'][ip][port] = server.instance
    LOG_ACTION(logger, 'Created {} TCP socket server'.format(count), indent=1, action=False)
    
    LOG_ACTION(logger, 'Running the side channel')
    side_channel.run(server_mapping, mappings)

def main():
    run(sys.argv)
    
if __name__=="__main__":
    main()
