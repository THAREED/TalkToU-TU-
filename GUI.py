from tkinter import *
from TalkToUTU import *
from PIL import ImageTk, Image
import os
import socket
import _thread as thread

master = 0
user_id = 0
user_pass = 0
USER_ADDR = 0
USER_PORT = 0
TCP_IP = socket.gethostbyname(socket.gethostname())
TCP_PORT = 1111

def loginWindow():
    master = Tk()
    master.title('TalkToU(TU)-Login')

    img = ImageTk.PhotoImage(Image.open("1.png"))
    panel = Label(master, image = img)   
    panel.grid(row=0, columnspan=5, sticky = E+N+S+W)

    userNameLabel = Label(master, text ="Username :", anchor = CENTER)
    userNameLabel.grid(row=1, column=1)

    userPassLabel = Label(master, text ="Password :", anchor = CENTER)
    userPassLabel.grid(row=2, column=1, sticky = W+E)

    userIPLabel = Label(master, text = "User IP :", anchor = CENTER)
    userIPLabel.grid(row=3, column=1, sticky = W+E)

    userPortLabel = Label(master, text = "User port :", anchor = CENTER)
    userPortLabel.grid(row=4, column=1, sticky = W+E)

    userNameEntry = Entry(master, bd =5)
    userNameEntry.grid(row=1, column=2)

    userPassEntry = Entry(master, bd =5, show="*")
    userPassEntry.grid(row=2, column=2)

    userIPEntry = Entry(master, bd =5)
    userIPEntry.grid(row=3, column=2)

    userPortEntry = Entry(master, bd =5)
    userPortEntry.grid(row=4, column=2)
    
    #default login
    userNameEntry.insert(0, '5909610387')
    userPassEntry.insert(0, '0387')
    userIPEntry.insert(0, TCP_IP)
    userPortEntry.insert(0, str(TCP_PORT))

    user_id = userNameEntry.get()
    user_pass = userPassEntry.get()
    USER_ADDR = userIPEntry.get()
    USER_PORT = userPortEntry.get()
    
    #login button
    space = Label(master, text = "", anchor = CENTER)
    space.grid(row=5, column=1, sticky = W+E)
    loginBttn = Button(master, text ="LOGIN",bg = "#B53F07", command = lambda: friendListWindow(userNameEntry, userPassEntry, userIPEntry, userPortEntry) )
    loginBttn.grid(row=6, columnspan=5, sticky = N+S+W+E)
    master.mainloop()

def listen():
    listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenSocket.bind((TCP_IP, TCP_PORT))
    listenSocket.listen(1)
    
    while True:
        conn, addr = listenSocket.accept()
        print('Connection address:' + str(addr))
        thread.start_new_thread(chatWindow, (('You are a server talking to '+str(addr)), conn,)) ############### ConThread newchat

def friendListWindow(userNameEntry, userPassEntry, userIPEntry, userPortEntry):
    user_id = userNameEntry.get()
    user_pass = userPassEntry.get()
    USER_ADDR = userIPEntry.get()
    USER_PORT = userPortEntry.get()
    userInfo = getAuthenFormat(user_id, user_pass, USER_ADDR, USER_PORT)
    serverAddr = getServerAddr('server.config')

    #start thread
    authThread = authenThread(serverAddr, userInfo) ################## AuthenThread&Heartbeat
    authThread.start()

    thread.start_new_thread(listen,())################## ListenThread

    #make list window
    listWindow = Tk()
    listWindow.title('TalkToU(TU)-FriendList')

    friendLabel = Label(listWindow, text ="- Friends List -", anchor = CENTER)
    friendLabel.grid(row=0, columnspan=1)
    
    friendList = []
    while len(friendList) == 0:
        friendList = authThread.friendList
    friendList.pop()

    friendSB = Scrollbar(listWindow) 
    friendLB = Listbox(listWindow, height = 30, width = 40, yscrollcommand = friendSB.set, selectbackground="#B53F07",highlightcolor="#B53F07")


    i = 1
    for line in friendList:
        friendLB.insert(i, line)
        i += 1

    friendLB.grid(row=1, column=0)
    friendSB.grid(row=1, column=1, sticky=N+S)
    friendSB.config( command = friendLB.yview )
    
    def connecting(friendLB):
        c2cSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        info = friendLB.get(ACTIVE)
        name, addr = getInfo(info)

        print('Connection thread to ' + str(addr) + ' START!!')
        connect(c2cSocket, addr)
        print('Connected')

        nameLabel = Label(listWindow, text =name, anchor = CENTER)
        nameLabel.grid(row=0, column=2)

        messages = Text(listWindow, height = 30, width = 48, background="#FFFACD", foreground="#27408B", state=DISABLED)
        messages.grid(row=1, column=2, sticky=N+S)

        #sent msg
        input_user = StringVar()
        sentmsg = Entry(listWindow, textvariable=input_user)
        sentmsg.grid(row=2, column=2, sticky=W+E)

        thread.start_new_thread( recvMsg, (c2cSocket, messages))

        def Enter_pressed(event):
            input_get = sentmsg.get()
            print(input_get)
            sent(c2cSocket, input_get)
            messages.configure(state='normal')
            sender_msg = str(input_get)
            messages.insert(INSERT, sender_msg.rjust(48,' ')) #sender msg
            messages.insert(INSERT, "\n") #sender msg
            messages.configure(state='disable')
            input_user.set('')
            sentmsg.delete(0, END)
            return "break"

        sentmsg.bind("<Return>", Enter_pressed)
        connectBttn.configure(state='disable', bg="#FFE4C4")

    #connect button
    connectBttn = Button(listWindow, text = 'CONNECT',  bg = "#B53F07", command = lambda: connecting(friendLB))
    connectBttn.grid(row=2, columnspan=2, sticky=W+E)
    
    def on_closing():
        authThread.c2sSocket.close()
        listWindow.destroy()
    
    listWindow.protocol("WM_DELETE_WINDOW", on_closing)
    listWindow.mainloop()

def recvMsg(c2cSocket, messages):
    while True:
        try:
            data = recv(c2cSocket)
            print(data)
            messages.configure(state='normal')
            messages.insert(INSERT, '%s\n' % data) #recv msg
            messages.configure(state='disable')
        except socket.error:
            pass

def chatWindow0(friendLB):
    c2cSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    info = friendLB.get(ACTIVE)
    name, addr = getInfo(info)

    print('Connection thread to ' + str(addr) + ' START!!')
    connect(c2cSocket, addr)
    print('Connected')

    chatWindow(name, c2cSocket)


def chatWindow(name, c2cSocket):
    print('Select: ' + name)

    chatWD = Tk()
    chatWD.title('TalkToU(TU)-'+name)

    messages = Text(chatWD,background="#CAE1FF", foreground="#27408B", state=DISABLED)
    messages.pack()

    thread.start_new_thread( recvMsg, (c2cSocket, messages, ) ) ##########In ConThread waiting msg 

    input_user = StringVar()
    input_field = Entry(chatWD,textvariable=input_user) #input from user
    input_field.pack(side=BOTTOM, fill=X)
    
    def Enter_pressed(event):
        input_get = input_field.get()
        print(input_get)
        sent(c2cSocket, input_get)
        messages.configure(state='normal')
        sender_msg = str(input_get)
        messages.insert(INSERT, sender_msg.rjust(240,' ')) #sender msg
        messages.insert(INSERT, "\n") #sender msg
        messages.configure(state='disable')
        input_user.set('')
        input_field.delete(0, END)
        return "break"
    
    frame = Frame(chatWD)  # , width=300, height=300)
    input_field.bind("<Return>", Enter_pressed)
    frame.pack()
    

    #try:
    #thread.start_new_thread( recvMsg, (c2cSocket, messages, ) )
    #except:
        #print("Error: unable to start thread")


    chatWD.mainloop()

loginWindow()
