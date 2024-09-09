import requests
import argparse
import subprocess
import os

# Define color codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    ORANGE = '\033[33m'  # ANSI color code for yellow (closest to orange)
    RESET = '\033[0m'

# Argument parser
parser = argparse.ArgumentParser()
parser.add_argument('-i', action='store', dest='IP', required=False, default='127.0.0.1', help='Mobile IP, default is 127.0.0.1')
parser.add_argument('-p', action='store', dest='port', required=False, default='5555', help='ADB port, default is 5555')
parser.add_argument('-c', action='store', dest='CertPath', required=True, help='Certificate file to push to the mobile device in der format')
parser.add_argument('-proxy', action='store', dest='proxy', required=False, default=':0', help='Proxy Settings, ex:127.0.0.1:8080 , default: no proxy')
arguments = parser.parse_args()

def print_status(message, success=True, color=Colors.GREEN):
    """Prints a message with the specified color."""
    print(f"{color}{message}{Colors.RESET}")

def get_latest_release_version(repo_url):
    """Fetches the latest release version from GitHub."""
    try:
        api_url = f"https://api.github.com/repos/{repo_url}/releases/latest"
        response = requests.get(api_url)
        response.raise_for_status()
        release_info = response.json()
        latest_version = release_info['tag_name']
        return latest_version
    except requests.RequestException as e:
        print_status(f"[-] Error fetching release info: {e}", color=Colors.RED)
        return None

def download_frida(version, arch):
    """Downloads and installs the latest Frida server."""
    try:
        print_status("[+] Downloading latest version of frida server ...")
        url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{arch}.xz"
        response = requests.get(url, stream=True)
        response.raise_for_status()
        filename = "frida-server.xz"
        with open(filename, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        print_status(f"[+] File downloaded successfully: {filename}")
        command0= "xz -v -d frida-server.xz"
        execute_command(command0)
        print_status("[+] Moving frida-server to the mobile ")
        command = "adb push frida-server /data/local/tmp/frida-server"
        execute_command(command)
        print_status("[+] Extracting frida-server ... ")
        command3 = "adb shell chmod +x /data/local/tmp/frida-server"
        execute_command(command3)
        print_status("[+] Frida server Extracted successfully!")
        push_cert()
    except FileExistsError as e:
        None 
    except requests.RequestException as e:
        print_status(f"[-] Error occurred: {e}", color=Colors.RED)

def execute_command(command):
    """Executes a shell command and returns its output."""
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = process.communicate()
        output = stdout.decode('utf-8').strip()
        error_output = stderr.decode('utf-8').strip()
        if process.returncode == 0:
            return output
        else:
            print_status(f"[-] Error occurred: {error_output}", color=Colors.RED)
            return None
    except Exception as e:
        print_status(f"[-] Exception occurred: {e}", color=Colors.RED)
        return None

def getMobileArch():
    """Fetches the mobile architecture and downloads Frida server."""
    command = "adb shell getprop ro.product.cpu.abi"
    arch = execute_command(command)
    frida_latest_version = get_latest_release_version("frida/frida")
    download_frida(frida_latest_version, arch)

def getAndroidVersoin():
    with os.popen('adb shell getprop ro.build.version.release') as pipe:
        output = pipe.read().strip()
    return output

def push_cert():
    """Pushes the certificate to the mobile device."""

    cert_path = arguments.CertPath
    checkFile = os.path.isfile(cert_path)
    print_status("[+] Checking Certificate ...", color=Colors.GREEN)
    if checkFile == True:

    	command = f"adb push {cert_path} /data/local/tmp/cert-der.crt"
    	print_status("[+] Pushing certificate to the mobile!")
    	execute_command(command)
    	print_status("[+] Certificate pushed to the mobile!")
    	if arguments.proxy == ":0":
        	print_status("[+] No proxy settings required")
        	print_status("[+] Exiting")
        	return
    	else:
        	print_status("[+] Proxy settings required, setting up proxy ...")
        	set_proxy()
    else:
    	print_status("[-] Certificate file does not exist, please check the path of the certificate and try again", color=Colors.RED)
    	print_status("[+] Exiting!", color=Colors.GREEN)
def set_proxy():
    """Sets up proxy settings on the mobile device."""
    print_status("[+] Setting up proxy ...")
    if getAndroidVersoin() == "12":
        command = "adb mount -o remount, rw /"
    else: 
        command = "adb remount"
    execute_command(command)
    command2= "openssl x509 -inform der -in {cert_path} -out 9a5ba575.0"
    execute_command(command)
    command3 = f"adb push 9a5ba575.0 /system/etc/security/cacerts"
    execute_command(command3)
    command4 = f"adb shell settings put global http_proxy {arguments.proxy}"
    execute_command(command4)
    print_status("[+] All set!")
    print_status("Note: to remove proxy settings, use this command: adb shell settings put global http_proxy :0", color=Colors.ORANGE)

def main(mobileIp, port):
    """Main function to connect to the mobile and start the setup."""
    connect_string = f"timeout 15 adb connect {mobileIp}:{port}"
    print_status(f"[*] Connecting to {mobileIp}:{port} ...")
    result = execute_command(connect_string)
    if result is None:
        print_status("[-] Connection failed, please check the mobile IP and the ADB port", color=Colors.RED)
    elif "connected" in result.strip():
        print_status("[+] Connected Successfully!")
        print_status("[+] Getting mobile architecture ...")
        getMobileArch()
    else:
        print_status("[-] Connection failed, please check the mobile IP and the ADB port", color=Colors.RED)
droidHacker="""

______           _     _ _   _            _             
|  _  \         (_)   | | | | |          | |            
| | | |_ __ ___  _  __| | |_| | __ _  ___| | _____ _ __ 
| | | | '__/ _ \| |/ _` |  _  |/ _` |/ __| |/ / _ \ '__|
| |/ /| | | (_) | | (_| | | | | (_| | (__|   <  __/ |   
|___/ |_|  \___/|_|\__,_\_| |_/\__,_|\___|_|\_\___|_|   
                                                        
By Mohammad Aldweik & Obada Suliman                                                        

"""
print_status(droidHacker,color= Colors.GREEN)
main(arguments.IP, arguments.port)
