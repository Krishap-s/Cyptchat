import sys
import argparse
import socket
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto import Random
import os
import hashlib
import base64
import select
global KEY
global server_socket
fkey = Fernet.generate_key()
den = os.urandom(5)

class aeso(object):

    def __init__(self, key): 
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        iv = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return base64.b64encode(cipher.encrypt(iv + raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return cipher.decrypt(enc[16:])

class verify(object):

    def __init__(self):
        self.key = KEY
    
    def host(self,c,addr):
      try :
        a = aeso(KEY)
        global f
        f = Fernet(fkey)
        print "[*] Verifying client",addr
        test = Fernet.generate_key()
        ekey = a.encrypt(fkey)
        etest = a.encrypt(test)
        c.send(etest)
        ans = c.recv(1024)
        if ans == test:
         print "[+] Client with address ",addr," is verified"
         c.send(ekey)
         eUser = c.recv(1024)
         User = a.decrypt(eUser)     
         return User
        else :
         print "[-] Client with address ",addr," is not verified"
         print "[-] Clossing connection ..."
         c.send("den")
         c.close
         return den
      except Exception,e :
         print "[!] Verification error REASON =",e
         return den
    def client(self,s):
        print "[+] Connection established"
        r = s.recv(1024)
        print "[+] Recieved Challenge from host"
        print "[*] Decrypting Auth test with key :",KEY
        a = aeso(KEY)
        res = a.decrypt(r)
        s.send(res)
        marks = s.recv(1024)
        if marks == "den" :
           print "[-] auth with server failed res = WRONG_KEY"
           exit();
        else:
           print"[+] auth with server success !!"
           s.send(a.encrypt(user))
           marks = a.decrypt(marks)
           global f
           f = Fernet(marks)
           

def host() :
    print "[*] Creating chat room ..."
    try :
         global server_socket
         global SOCKET_LIST
         SOCKET_LIST = []
         server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
         server_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
         server_socket.bind((HOST, PORT))
         server_socket.listen(10)
         SOCKET_LIST.append(server_socket)
         print "[+] Chat room created succesfully on ( ",HOST,":",PORT," )!!"
         print "[*] Listening for connections ..."
    except Exception, e:
         print "[!] Chat room could not be made REASON :",e
    Chatroom().handle()
def client ():
   s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
   try :
      print "[*] Connecting to chatroom ..."
      s.connect((HOST,PORT))
      verify().client(s)
   except Exception ,e :
      print "[!] ERROR CONNECTING REASON:",e
      exit()
   
   Chatroom().client(s)
      

class Chatroom (object) :

   def __init__(self) :
      self.dbs = []
   
   def handle(self) :
    try :
        while 1:

        # get the list sockets which are ready to be read through select
        # 4th arg, time_out  = 0 : poll and never block
           ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)
      
           for sock in ready_to_read:
            # a new connection request recieved
               if sock == server_socket: 
                sockfd, addr = server_socket.accept()
                global user
                user = verify().host(sockfd,addr)
                if user == den :
                  continue
                SOCKET_LIST.append(sockfd)
                print "[+] Client with username " + user + "(%s, %s) connected" % addr
                 
                self.broadcast(sockfd,"\r" + user + "[%s:%s] entered our chatting room\n" % addr)
             
            # a message from a client, not a new connection
               else:
                # process data recieved from client, 
                try:
                    # receiving data from the socket.
                    eUser = sock.recv(4096)
                    if eUser == None :
                       self.broadcast(sock, "\r" + sock.getpeername() + " is offline\n")   
                       continue
                    edata = sock.recv(4096)
                    global User
                    User = f.decrypt(eUser)
                    data = f.decrypt(edata)
                    if data:
                        # there is something in the socket
                        self.broadcast(sock, "\r" + User + " >> "+ data)  
                    else:
                        # remove the socket that's broken    
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)

                        # at this stage, no data means probably the connection has been broken
                        self.broadcast(sock, "\r" + User + " is offline\n") 
                        print "[-] Client ",addr, "disconnected"
                # exception 
                except Exception ,e:
                    self.broadcast(sock, "\r" + User + " is offline\n")
                    SOCKET_LIST.remove(sock)
                    print "[-] Client",addr," diconnected"
                    continue
    except KeyboardInterrupt :
       print "[+] Shutting Down Server"
       exit()
       
   def broadcast(self,s,mess):
      for socket in SOCKET_LIST :
        # send the message only to peer
        if socket != server_socket and socket != s :
            try :
                socket.send(f.encrypt(mess))
            except Exception ,e:
                # broken socket connection
                socket.close()
                # broken socket, remove it
                if socket in SOCKET_LIST:
                    SOCKET_LIST.remove(socket)

   def client (self,s):
       os.system('clear')
       print 'Connected to remote host. You can start sending messages'
       sys.stdout.write('[Me] '); sys.stdout.flush()
     
       while 1:
           try :
              socket_list = [sys.stdin, s]
              
        # Get the list sockets which are readable
              ready_to_read,ready_to_write,in_error = select.select(socket_list , [], [])
              
              for sock in ready_to_read:             
                  if sock == s:
                   # incoming message from remote server, s
                      edata = sock.recv(4096)
                      if not edata :
                          print '\nDisconnected from chat server'
                          sys.exit()
                      else :
                    #print data
                          data = f.decrypt(edata)
                          sys.stdout.write(data)
                          sys.stdout.write('[Me] '); sys.stdout.flush()     
              
                  else :
                # user entered a message
                      msg = sys.stdin.readline()
                      s.send(f.encrypt(user))
                      s.send(f.encrypt(msg))
                      sys.stdout.write('[Me] '); sys.stdout.flush()
           except KeyboardInterrupt :
              print "\r[-] Disconnecting"
              s.send(f.encrypt(user))
              exit()
  

parse = argparse.ArgumentParser(description="Creates a encrypted chat room without a middle man or server")
parse.add_argument('-t','--type',type=str,help='Type of machine[H = host ,C = client]')
parse.add_argument('-p','--port',type=int,help='Port num')
parse.add_argument('-H','--Host',type=str,help='Host IP or URL')
parse.add_argument('-U','--User',type=str,help='Username')
parse.add_argument('-k','--key',type=str,help='key')      
args = parse.parse_args()
typ = args.type
PORT = args.port
user = args.User
HOST = args.Host
KEY = args.key   
if typ == None or PORT == None or HOST == None or user == None :
   parse.print_usage()
   exit()

if typ == "H" :
    host()
elif typ == "C" :
    client()

         
                     
         
