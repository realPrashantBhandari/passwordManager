import os
import PySimpleGUI as sg 
import csv
import time
import base64
import ast
import random
import string
from io import StringIO
import shutil
from tempfile import NamedTemporaryFile
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

cwd = os.getcwd()
cwd = cwd.replace('\\', '/')
credentialFile = str(cwd +'/credentials.csv')

class Gui:
    def __init__(self):
        self.currentUser = ''
        

    def mainWindow(self):
        self.mainLayout=[
            [
                sg.Text('Enter Username',size=(20,1), justification='center'),
                sg.Input(size=(20,1), focus=True, key = "-MASTERUSERNAME-")
            ],
            [
                sg.Text('Enter Password',size=(20,1), justification='center'),
                sg.Input(size=(20,1),password_char='*', key = "-MASTERPASSWORD-")
            ],
            
            [
                sg.Button('LogIn',size=(20,1), key = "-LOGIN-",bind_return_key=True),
                sg.Button('Sign up',size=(20,1), key = "-SIGNUP-"),
            ]
        ]

        self.window = sg.Window('Password Manager').Layout(self.mainLayout)
      
    def secondWindow(self):

        self.rpg_layout =[
            [ sg.Slider(range=(4,16),orientation='h', default_value=12, key='-PASSWORDLENGTH-') ],
            [ sg.Text('Special Characters',size=(20,1), justification='center')],
            [ sg.Input(size=(25,1),justification='center', key='-SPLCHAR-')],
            [sg.Button('Generate New Password',size=(22,1), key='-GENERATE-')]
        ]
        ## Left column
        self.left_col =[
            [
                sg.Text('Current User:',size=(10,1),justification='center'),
                sg.Text(self.currentUser,size=(10,1),justification='center', key='-CURRENT-')
            ],
            [sg.Text('Enter Website',size=(20,1),justification='center')],
            [sg.Input(size=(25,1), focus=True,justification='center', key='-WEBSITE-')],
            [sg.Text('Enter Username',size=(20,1),justification='center')],
            [sg.Input(size=(25,1),justification='center', key='-USERNAME-')],
            [sg.Text('Enter Password',size=(20,1),justification='center')],
            [sg.Input(size=(25,1),justification='center', key='-PASSWORD-')],
            [
                sg.Button('Add',size=(10,1), key = "-ADD-"),
                sg.Button('Update',size=(10,1), key = "-UPDATE-"),
            ],
            [
                sg.Frame('Random Password Generator', self.rpg_layout)
            ],
            
        ]

        ## Right Column
        self.right_col =[
            [
                sg.Text('Saved Credentials',size=(20,1),justification='center')
            ],
            [
                sg.Output(size=(30,20), key='-OUTPUT-',echo_stdout_stderr = True)
            ]
        ]
        self.layout2 = [
            [sg.Column(self.left_col),sg.VSeparator(),sg.Column(self.right_col,vertical_alignment='top')]
        ]

        self.window = sg.Window("Second Window", modal=True).Layout(self.layout2)
        

    def signupWindow(self):
        self.signupLayout=[
            [
                sg.Text('Enter new Master Username',size=(20,1), justification='center'),
                sg.Input(size=(20,1), focus=True, key = "-NEWMASTERUSERNAME-")
            ],
            [
                sg.Text('Enter new Master Password',size=(20,1), justification='center'),
                sg.Input(size=(20,1), key = "-NEWMASTERPASSWORD-")
            ],
            [
                sg.Button('SUBMIT',size=(20,1), key = "-SUBMITNEWMASTERPASSWORD-"),
                sg.Button('Cancel',size=(20,1), key = "Exit")
            ]
        ]

        self.window2 = sg.Window("Sign UP Window", modal=True).Layout(self.signupLayout)

    def popupWindow(self,msg):
        sg.popup(msg, keep_on_top=True,auto_close=True,auto_close_duration=2)

class Enc:
    def __init__(self):
        self.currentPassword = b''
        self.currentUsername = ''
        self.providedWebsite = ''
        self.providedUsername = ''
        self.providedPassword = ''

    def generateKey(self,data):
        passwordProvided = data[2]
        password= passwordProvided.encode()

        salt = b'\x92\xb5\x13\xb8\x1f\x87)l\x8cl\x9fY\xa2\xbe\x9a\xfd'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        tempKey = base64.urlsafe_b64encode(kdf.derive(password))
        csvData = ['master',data[1],tempKey,data[3]]
        
        return csvData

    def updateEntry(self,dataToUpdate):
        f = Fernet(self.currentPassword)
        dataEncoded = [dataToUpdate[0],dataToUpdate[1].encode(),dataToUpdate[2].encode(),dataToUpdate[3].encode()]
        dataEncoded[1] = f.encrypt(dataEncoded[1])
        dataEncoded[2] = f.encrypt(dataEncoded[2])
        dataEncoded[3] = f.encrypt(dataEncoded[3])

        tempfile = NamedTemporaryFile('w+t',newline='', delete=False)
        
        with open(credentialFile,'r') as File, tempfile:
            reader = csv.reader(File)
            writer = csv.writer(tempfile)

            for row in reader:
                tempRow = []
                
                if (row[0] == str(dataToUpdate[0])):

                    if (row[3] == dataToUpdate[3]):
                        print('THERE')
                        row[1] = dataEncoded[1]
                        row[2] = dataEncoded[2]

                        #print(dataEncoded[1])

                writer.writerow(row)
        print(tempfile.name)
        shutil.move(tempfile.name,credentialFile)
                    

    def encodeEntry(self,dataToEncode):
        FLAG = True
        if checkAdd(dataToEncode) == False :
            FLAG = False
        else:
            ## Encrypting the data
            f = Fernet(self.currentPassword)
            dataEncoded = [dataToEncode[0],dataToEncode[1].encode(),dataToEncode[2].encode(),dataToEncode[3]]
            dataEncoded[1] = f.encrypt(dataEncoded[1])
            dataEncoded[2] = f.encrypt(dataEncoded[2])
            appedToCSV(dataEncoded)
            FLAG = True

        return FLAG

    def decodeEntry(self, dataToDecode):
        
        tempData = dataToDecode
        f2 = Fernet(self.currentPassword)
        ## converting strings read by csv.read to bytes
        tempData[1] = ast.literal_eval(tempData[1])
        tempData[2] = ast.literal_eval(tempData[2])

        ## decrypting the bytes msg
        tempData[1] = f2.decrypt(tempData[1])
        tempData[2] = f2.decrypt(tempData[2])

        decodedData =[tempData[0],tempData[1].decode(),tempData[2].decode(),tempData[3]]

        return decodedData
    
    def printCredentials(self):
        with open(credentialFile,'r') as File:
            reader = csv.reader(File)
            for row in reader:
                if (row[0] == str(self.currentUsername)):
                    decodedData = self.decodeEntry(row)
                    print(decodedData[3].strip('b').replace("'", ""))
                    print("> {} ".format(decodedData[1]))
                    print(">> {} ".format(decodedData[2]))
                    print()


def appedToCSV(data):
    with open(credentialFile,'a',newline='') as File:
        writer = csv.writer(File)
        writer.writerow(data)

def checkSignup(data):
    FLAG = True
    with open(credentialFile,'r') as File:
        reader = csv.reader(File)
        for row in reader:

            if (row[0]==data[0]):
                
                if (row[1]==data[1]):
                    FLAG = False
                
                if (row[2]==data[2]):
                    FLAG = False    
    return FLAG

def checklogin(data):
    FLAG = True
    with open(credentialFile,'r') as File:
        reader = csv.reader(File)
        for row in reader:

            if (row[0]==data[0]):
                if (row[1]==data[1]):
                    if (row[2]==str(data[2])):
                        FLAG = False    
    return FLAG

def checkAdd(data):
    FLAG = True
    with open(credentialFile,'r') as File:
        reader = csv.reader(File)
        for row in reader:
            if (row[0]==data[0]):
                if (row[3]==data[3]):
                    FLAG = False    
    return FLAG

def generateRandomPassword(lenghtOfPassword, splCharList):
    splChar = ''.join(splCharList)
    splCounter = 0
    chars = string.ascii_letters + string.digits
    random.seed = os.urandom(1024)
    tempList = []
    for i in range(int(lenghtOfPassword)):
        if (i % 2 == 0 and splCounter < len(splCharList)) :
            tempList.append(splChar[splCounter])
            splCounter += 1
            #splCharList.remove(tempList[i])
            #print(type(splCharList))
        else:
            tempList.append(random.choice(chars))

    rngPassword = ''.join(tempList)
    return rngPassword

def main():
    g=Gui()
    g.mainWindow()
    encd = Enc()
    

    while True:
        event, values = g.window.Read()
    
        if event is None:
            break

        if event == '-SIGNUP-':
            g.signupWindow()
            while True:
                event, values = g.window2.read()
                if event == "Exit" or event == sg.WIN_CLOSED:
                    break

                if event == "-SUBMITNEWMASTERPASSWORD-":
                    data=['master',values['-NEWMASTERUSERNAME-'],values["-NEWMASTERPASSWORD-"],'passwordManager']
                    if (values['-NEWMASTERUSERNAME-'] != '' and values["-NEWMASTERPASSWORD-"] != ''):
                        encodedData = encd.generateKey(data)
                        if checkSignup(encodedData) == True:
                            appedToCSV(encodedData)
                            g.popupWindow('Credentials added successfully')
                        else:
                            g.popupWindow('Credentials already Exist')
                    else:
                        g.popupWindow('Enter Valid Credentials')
                
                    g.window2.close() 
 
            g.window2.close()  

        if event == "-LOGIN-":
            data=['master',values['-MASTERUSERNAME-'],values["-MASTERPASSWORD-"],'passwordManager']
            encodedData = encd.generateKey(data)
            if (checklogin(encodedData)== False):
                startup = 1  
                g.currentUser =  encodedData[1]
                g.secondWindow()
                
                while True:
                    if (startup == 1):
                        event,values = g.window.read(timeout=500)

                        encd.currentUsername = encodedData[1]
                        encd.currentPassword = encodedData[2]

                        encd.printCredentials()
                        startup =0
                    event, values = g.window.read() 
                    if event == "Exit" or event == sg.WIN_CLOSED:
                        break
                    if event == '-ADD-':
                        g.window['-OUTPUT-'].Update('')
                        encd.providedWebsite = values['-WEBSITE-']
                        encd.providedUsername = values['-USERNAME-']
                        encd.providedPassword = values['-PASSWORD-']
                        dataToEncode = [encd.currentUsername,encd.providedUsername,encd.providedPassword,encd.providedWebsite]
                        addFlag = encd.encodeEntry(dataToEncode)

                        if (addFlag == True):
                            encd.printCredentials()
                            g.window['-WEBSITE-'].Update('')
                            g.window['-USERNAME-'].Update('')
                            g.window['-PASSWORD-'].Update('')
                        else:
                            g.popupWindow('Website name already exist. Use different name or use the Update button')
                            encd.printCredentials()
                    if event == '-UPDATE-':
                        encd.providedWebsite = values['-WEBSITE-']
                        encd.providedUsername = values['-USERNAME-']
                        encd.providedPassword = values['-PASSWORD-']
                        dataToEncode = [encd.currentUsername,encd.providedUsername,encd.providedPassword,encd.providedWebsite]
                        encd.updateEntry(dataToEncode)
                        g.window['-OUTPUT-'].Update('')
                        g.window['-WEBSITE-'].Update('')
                        g.window['-USERNAME-'].Update('')
                        g.window['-PASSWORD-'].Update('')
                        encd.printCredentials()

                    if event == '-GENERATE-':
                        passwordLength = values['-PASSWORDLENGTH-']
                        splCharList = values['-SPLCHAR-']
                        rpgPassword = generateRandomPassword(passwordLength,splCharList)
                        g.window['-PASSWORD-'].Update(rpgPassword)
                    
                        
            else:
                g.popupWindow('Username and Password does not match')


    g.window.close()


if __name__ == '__main__':
    print('Starting program...')
    main()