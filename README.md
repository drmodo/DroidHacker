# DroidHacker
A tool that helps mobile pentesters to setup a mobile test environment 


![screenshot](logo.png)




## Key Features of Droid Hacker

* Download the Latest version: Obtain the most recent version of the Frida server for your mobile device.
* Grant Executable Permissions: Ensure the Frida server file has executable permissions.
* Copy the Certificate File: Place the certificate file in the Frida server’s directory (essential for full functionality).
* Configure Global Proxy Settings: Set up the global proxy settings on your device.
* Install the Certificate: Install the certificate on your mobile device for proper operation.
  
## Prerequisites

Before running the project, ensure you have the following tools and libraries installed:

### System Packages

On a Debian/Ubuntu-based system, you can install the required packages using:

```bash
sudo apt update && sudo apt install -y python3-pip adb xz-utils openssl
```
On a Red Hat/CentOS-based system, use:

```bash

sudo yum install -y python3-pip adb xz openssl
```
### Python Libraries

```bash
pip3 install requests

```
## Installation

Clone the repository:

```bash

git clone https://github.com/drmodo/DroidHacker.git
```
Navigate to the project directory:

```bash

cd DroidHacker
```
Run the Python file:

```bash
python3 droidhacker.py
```
### Usage:
```bash
droidhacker.py  -i <Mobile IP > -p <ADB Port> -c <certificate file in DER format> -proxy <IP:Port>
```
To run frida server: 

```bash
adb shell "/data/local/tmp/frida-server &" 
```
### Options:

| Flag  | Description|
| ------------- | ------------- |
| -h, --help  | show help message and exit  |
| -i IP | Mobile IP, default is 127.0.0.1 |
| -p PORT   |    ADB port, default is 5555|
| -c CERTPATH   |Certificate file to push to the mobile device in DER format|
|-proxy PROXY  |Proxy Settings, ex:127.0.0.1:8080 , default: no proxy|

## Demo


https://github.com/drmodo/DroidHacker1/blob/main/README.md
