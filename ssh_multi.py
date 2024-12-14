import os
import sys
import paramiko
import time
from datetime import datetime
from getpass import getpass
from scp import SCPClient, SCPException
from Crypto import Crypto
from concurrent.futures import ThreadPoolExecutor
import hashlib
import pyminizip
import shutil

STOP_HOSTNAME = True
RUN_MULTITHREADING = False
BACKUP_CONFIG = False

class Ssh():
    def __init__(self, ip, hostname, port, user, password):
        self.crypto = Crypto()
        self.ip = ip
        self.hostname = hostname
        self.port = port
        self.user = self.crypto.encrypt_random_key(user)
        self.password = self.crypto.encrypt_random_key(password)
        self.sleepTimeCommand = 0.2
        self.sleepTimeBanner = 1
        self.maxIterations = 1000
        self.bufferSize = 10000
        self.printBanner = False
        self.client = None
        self.shell = None
        self.scp = None

        # stop list single char
        self.stopList = [">", "%", "#", "$"]

        # stop list hostname followed by a stop char
        self.stopListHostname = []
        self.stopCharsHostname = [">", "%", "#", "$", "(", ")" , ":", " >", " %", " #", " $", " (", " )" , " :"]
        self.generateStopListHostname()

    def getResponse(self, shell):
        count = 0
        recv_len = 1
        output = ""
        data = bytearray()
        while recv_len:
            time.sleep(self.sleepTimeCommand)
            if shell.recv_ready():
                data = shell.recv(self.bufferSize)
                recv_len = len(data)
                output += data.decode("utf-8")
            if STOP_HOSTNAME:
                # STOP BY HOSTNAME
                # check if hostname followed by stop char is in the data received and if stop char is in the last 2 chars of the data
                if recv_len < self.bufferSize and any(l in data.decode("utf-8") for l in self.stopListHostname) and any(l in data.decode("utf-8")[-2:] for l in self.stopCharsHostname):
                    break
                # check if hostname followed by stop char is in the whole output and if stop char is in the last 2 chars of the data
                if recv_len < self.bufferSize and any(l in output for l in self.stopListHostname) and any(l in data.decode("utf-8")[-2:] for l in self.stopCharsHostname):
                    break
            else:
                # STOP BY SINGLE CHAR
                # check if stop char is in the last 2 chars of the data received
                if recv_len < self.bufferSize and any(l in data.decode("utf-8")[-2:] for l in self.stopList):
                    break
            if count == self.maxIterations:
                output += "!!!!!!!!! Too many iterations for reading output !!!!!!!!!"
                break
            count += 1
        return output

    def runCommand(self, com):
        self.shell.send(com)
        out = self.getResponse(self.shell)
        return out

    def generateStopListHostname(self):
        for l in self.stopCharsHostname:
            self.stopListHostname.append(f"{self.hostname}{l}")

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.ip, self.port, self.crypto.decrypt_random_key(self.user), self.crypto.decrypt_random_key(self.password))
        self.shell = self.client.invoke_shell(height=100, width=100)

    def printOutput(self, out, file):
        for line in out.splitlines():
            print(line)
            file.write(line + "\n")

    def close(self):
        self.client.close()
        self.shell.close()

    def connectScp(self):
        self.scp = SCPClient(self.client.get_transport())

    def downloadFile(self, file, path):
        self.scp.get(file, path)

    def uploadFile(self, file, path):
        self.scp.put(file, path, recursive=True)

    def closeScp(self):
        self.scp.close()

    def exportF5Ucs(self, device, destinationDir, logFile, time):
        self.maxIterations = 3000
        fileName = device + "_" + time + ".ucs"
        out = self.runCommand(f"save /sys ucs {fileName} passphrase XXXXX" + "\n")
        self.printOutput(out, logFile)
        self.connectScp()
        self.downloadFile(f"/var/local/ucs/{fileName}", f"{destinationDir}/{fileName}")
        out = self.runCommand("bash" + "\n")
        self.printOutput(out, logFile)
        out = self.runCommand(f"md5sum /var/local/ucs/{fileName}" + "\n")
        self.printOutput(out, logFile)
        original_hash = out.splitlines()[2].split(" ")[0]
        downloaded_hash = hashlib.md5(open(f"{destinationDir}/{fileName}",'rb').read()).hexdigest()
        print(f"[*] original hash:{original_hash}")
        print(f"[*] downloaded hash:{downloaded_hash}")
        logFile.write(f"[*] original hash:{original_hash}" + "\n")
        logFile.write(f"[*] downloaded hash:{downloaded_hash}" + "\n")
        if original_hash == downloaded_hash:
            print("[*] Hash is good")
            logFile.write("[*] Hash is good" + "\n")
        else:
            print("[*] Hash is bad")
            logFile.write("[*] Hash is bad" + "\n")
        out = self.runCommand(f"rm -f /var/local/ucs/{fileName}\n")
        self.printOutput(out, logFile)

    def exportFortigateConfig(self, device, destinationDir, logFile, time):
        fileName = device + "_" + time + ".conf"
        out = self.runCommand("config global" + "\n")
        self.printOutput(out, logFile)
        out = self.runCommand(f"execute backup config ftp Ssh_multi/{destinationDir}/{fileName} 10.10.10.1 ftp_user XXXXX" + "\n")
        self.printOutput(out, logFile)
        out = self.runCommand("end" + "\n")
        self.printOutput(out, logFile)

    def exportFortimgmtConfig(self, device, destinationDir, logFile, time):
        fileName = device + "_" + time + ".dat"
        out = self.runCommand(f"execute backup all-settings ftp 10.10.10.1:21 Ssh_multi/{destinationDir}/{fileName} ftp_user XXXXX" + "\n")
        self.printOutput(out, logFile)


    @staticmethod
    def zip(input_files, output, password):
        # flat files
        compress_level = 5
        pyminizip.compress_multiple(input_files, [], output, password, compress_level)

    @staticmethod
    def unzip(zip_file, password, unzip_dest=""):
        # if the dest directory for unzip is not set, then set it as the source zip file name
        if not unzip_dest:
            unzip_dest = zip_file.split(".zip")[0]

        if not os.path.exists(unzip_dest):
            os.makedirs(unzip_dest)

        pyminizip.uncompress(zip_file, password, unzip_dest, 0)

    @staticmethod
    def deleteFolder(folderName):
        shutil.rmtree(folderName)

    @staticmethod
    def runCommandsOnDevice(device, commands, username, password, mainDir, outputDir, dir, now, logFile, mainCrypto):
        # dir and now parameters are used for BACKUP_CONFIG
        ip = device.split("---")[0]
        hostname = device.split("---")[1]
        port = device.split("---")[2]
        outFilePerDevice = open(f"{mainDir}/{outputDir}/{hostname}.txt", "w", encoding="utf-8")
        print (f"[*] {device}")
        logFile.write(f"[*] {device}" + "\n")

        ssh = Ssh(ip, hostname, port, mainCrypto.decrypt_random_key(username), mainCrypto.decrypt_random_key(password))
        ssh.connect()

        output = ssh.getResponse(ssh.shell)
        if ssh.printBanner:
            ssh.printOutput(output, outFilePerDevice)

        prompt = ssh.runCommand("\n")    
        print(prompt)
        outFilePerDevice.write(prompt + "\n")    

        for command in commands:
            if command.startswith("#"): continue
            out = ssh.runCommand(command + "\n")
            ssh.printOutput(out, outFilePerDevice)
        outFilePerDevice.close()

        # ssh.connectScp()
        # ssh.downloadFile("/tmp/date_tmp", "date_tmp")
        # ssh.uploadFile("date_tmp_old", "/tmp/date_tmp_old")
        # ssh.closeScp()

        if BACKUP_CONFIG:
            if dir == "f5": ssh.exportF5Ucs(hostname, f"{mainDir}/{outputDir}", logFile, now)
            if dir == "fortigate": ssh.exportFortigateConfig(hostname, f"{mainDir}/{outputDir}", logFile, now)
            if dir == "fortimgmt": ssh.exportFortimgmtConfig(hostname, f"{mainDir}/{outputDir}", logFile, now)

        ssh.close()

    @staticmethod
    def iterate():
        mainDir = sys.argv[1]
        print(f"[*] {mainDir}")
        mainCrypto = Crypto()
        # port = 22
        user = mainCrypto.encrypt_random_key(getpass("Enter user"))
        passw = mainCrypto.encrypt_random_key(getpass("Enter password"))

        if BACKUP_CONFIG: zip_password = mainCrypto.encrypt_random_key(getpass("Enter zip password"))

        now = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        outputDir = f"output/output-{now}"
        if not os.path.exists(f"{mainDir}/{outputDir}"):
            os.mkdir(f"{mainDir}/{outputDir}")

        logFile = open(f"{mainDir}/{outputDir}/log.txt", "w")
        logFile.write(f"[*] {mainDir}" + "\n")

        for dir in os.listdir(f"{mainDir}/ssh"):
            if dir.startswith("#"): continue
            print(f"[*] {dir}")
            logFile.write(f"[*] {dir}" + "\n")

            commandsFile = open(f"{mainDir}/ssh/{dir}/commands.txt", 'r')
            devicesFile = open(f"{mainDir}/ssh/{dir}/devices.txt", 'r')
            commands = commandsFile.read().splitlines()
            devices = devicesFile.read().splitlines()
            commandsFile.close()
            devicesFile.close()

            print(f"[*] Devices: {devices}")
            print(f"[*] Commands to run: {commands}")
            logFile.write(f"[*] Devices: {devices}" + "\n")
            logFile.write(f"[*] Commands to run: {commands}" + "\n")

            username = user
            password = passw

            if RUN_MULTITHREADING:
                #parallel threads per devices directory
                with ThreadPoolExecutor(max_workers=10) as executor:
                    for device in devices:
                        if device.startswith("#"): continue
                        future = executor.submit(Ssh.runCommandsOnDevice, device, commands, username, password, mainDir, outputDir, dir, now, logFile, mainCrypto)
            else:
                for device in devices:
                    if device.startswith("#"): continue
                    Ssh.runCommandsOnDevice(device, commands, username, password, mainDir, outputDir, dir, now, logFile, mainCrypto)

        print("\n[*] DONE!\n")
        logFile.write("\n[*] DONE!\n")
        logFile.close()

        if BACKUP_CONFIG:
            ##### zip with password #####
            time.sleep(120)
            filepaths_for_zip = []
            filenames_for_zip = os.listdir(f"{mainDir}/{outputDir}")
            for file in filenames_for_zip:
                filepaths_for_zip.append(f"{mainDir}/{outputDir}/{file}")
            zip_file_name = f"{mainDir}/{outputDir}.zip"

            print("[*] Zipping output files...")
            print(*filepaths_for_zip, sep="\n")
            Ssh.zip(filepaths_for_zip, zip_file_name ,mainCrypto.decrypt_random_key(zip_password))

            time.sleep(5)
            print("[*] Deleting output files...")
            Ssh.deleteFolder(f"{mainDir}/{outputDir}")


def main():
    start = time.perf_counter()
    if len(sys.argv) == 2:
        Ssh.iterate()
    else:
        print("Run ssh_multi.py <folder name>")
    end = time.perf_counter()
    print(f"Total time: {end - start}")

if __name__ == "__main__":
    main()