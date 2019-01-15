
import socket
import threading

#c2sSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#c2cSockets = []
#listenSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

################################# get function #################################

def getServerAddr(fileName):
  array = []
  with open(fileName, "r") as f:
      for line in f:
        array.append(line)
  UDP_IP = array[0][:-1]
  UDP_PORT = int(array[1])
  print(UDP_IP)
  print(UDP_PORT)
  return (UDP_IP, UDP_PORT)

def getAuthenFormat(user_id, user_pass, USER_ADDR, USER_PORT):
  userInfo = "USER:" + user_id + "\n" + \
  "PASS:" + user_pass + "\n" + \
  "IP:" + USER_ADDR + "\n" + \
  "PORT:" + USER_PORT + "\n"
  return userInfo

def getInfo(friendInfo):
    data = friendInfo.split(':')
    return data[0],(data[1], int(data[2]))

############################### connection function ###########################

def connect(socket, addr):
    print(str(addr))
    socket.connect(addr)

def authentication(c2sSocket, userInfo):
  c2sSocket.send(bytes(userInfo, 'utf-8'))
  print("sending Authentication...")
  print(userInfo)

  try:
    status = c2sSocket.recv(4096).decode('utf-8')
    earlyList = status
    status = status[:11]
    print(status)
  except socket.timeout:
    print('REQUEST TIMEOUT')
  return status == '200 SUCCESS', earlyList 

def heartbeat(c2sSocket):
    try:
        while True:
            data = c2sSocket.recv(4096).decode('utf-8')
            print('Server say: ' + data)
            c2sSocket.send(bytes('Hello Server', 'utf-8'))
            print('Client response: Hello Server')
    except socket.error as err:
        print('Socket error: {0}'.format(err))

def getFriendList(c2sSocket, earlyList):
    data = earlyList
    while data[-4:-1] != 'END':
        data += c2sSocket.recv(4096).decode('utf-8')
    ans = data.split()
    ans.pop(0)
    ans.pop(0)
    #ans.pop()
    return ans

def recv(c2cSocket):
    return c2cSocket.recv(4096).decode('utf-8')

def sent(c2cSocket, message):
    c2cSocket.send(bytes(message, 'utf-8'))
############################# Thread ##########################################

class authenThread(threading.Thread):
    def __init__(self, serverAddr, userInfo):
        threading.Thread.__init__(self)
        self.c2sSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.c2sSocket.settimeout(60)
        self.serverAddr = serverAddr
        self.userInfo = userInfo
        self.friendList = []

    def run(self):
        print('Authentication and Heartbeat thread START!!')
        connect(self.c2sSocket, self.serverAddr)

        print('Already connect to ' + str(self.serverAddr))
        t, earlyList = authentication(self.c2sSocket, self.userInfo) 
        print('Authentication: ' + str(t))

        print('getting friend list...')
        self.friendList = getFriendList(self.c2sSocket, earlyList)
        for i in self.friendList:
            print(i)

        print('Heartbeat START!!')
        heartbeat(self.c2sSocket)

class connectThread(threading.Thread):
    def __init__(self, addr):
        threading.Thread.__init__(self)
        self.addr = addr
        self.c2cSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):
        print('Connection thread to ' + str(self.addr) + ' START!!')
        connect(self.c2cSocket, self.addr)
        print('Connected')

############################## main ###########################################
if __name__ == "__main__":
    user_id = "5909610387"
    user_pass = "0387"
    USER_ADDR = socket.gethostbyname(socket.gethostname())
    USER_PORT = "1111"

    userInfo = getAuthenFormat(user_id, user_pass, USER_ADDR, USER_PORT)
    print(userInfo)
    serverAddr = getServerAddr('server.config')
    
