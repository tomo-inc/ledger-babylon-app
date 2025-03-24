# Description: This script is used to install babylon app on Ledger devices.

# pyinstaller pack steps:
# 0. prepare all apdu files into ./apdu folder, file names are determined by get_file_name_by_target_id method
# 1. python -m venv venv
# 2. venv\Scripts\activate
# 3. pip install ledgerblue keyboard pyinstaller
# 4. pyinstaller babyloninst.spec
# 5. dist/babyloninst.exe is ready to use

# Device name and targetId mapping
# Device name        Firmware Version       Target ID
# Flex               all                    0x33300004
# Stax               all                    0x33200004
# Nano S Plus       all                    0x33100004
# Nano X (developer units only)    0x33000004
# Nano S <= 1.3.1    0x31100002
# Nano S 1.4.x       0x31100003
# Nano S >= 1.5.x    0x31100004
# Ledger Blue <= 2.0 0x31000002
# Ledger Blue 2.1.x  0x31000004
# Ledger Blue v2 2.1.x 0x31010004

import binascii
import sys
import os
import keyboard
from ledgerblue.comm import getDongle
from ledgerblue.deployed import getDeployedSecretV2
from ledgerblue.ecWrapper import PrivateKey
from ledgerblue.hexLoader import HexLoader

# Device name and targetId mapping
# Device name        Firmware Version       Target ID
# Flex               all                    0x33300004
# Stax               all                    0x33200004
# Nano S Plus       all                    0x33100004
# Nano X (developer units only)    0x33000004
# Nano S <= 1.3.1    0x31100002
# Nano S 1.4.x       0x31100003
# Nano S >= 1.5.x    0x31100004
# Ledger Blue <= 2.0 0x31000002
# Ledger Blue 2.1.x  0x31000004
# Ledger Blue v2 2.1.x 0x31010004

def get_apdu_file_path(file_name):
    """
    This function returns the path to the APDU file based on whether the program is 
    running from a bundled executable or from source code.
    - If running as an executable, it retrieves the file from the temporary extracted directory.
    - If running in development mode, it retrieves the file from the current directory.
    """
    # Check if the program is running from a bundled executable (PyInstaller)
    if hasattr(sys, '_MEIPASS'):
        # Get the base path from the temporary directory created by PyInstaller
        base_path = sys._MEIPASS
    else:
        # Use the current working directory when running from source
        base_path = os.path.abspath(".")

    # Join the base path with the relative path to the 'apdu' directory and file name
    file_path = os.path.join(base_path, "apdu", file_name)
    return file_path

def get_file_name_by_target_id(targetId):
    """
    This function returns the file name corresponding to the targetId of the Ledger device 
    and the name of the device.
    """
    # Match targetId to the corresponding device and return file name and device name
    if targetId == 0x33300004:
        device_name = "Ledger Flex"
        file_name = "flex.apdu"
    elif targetId == 0x33200004:
        device_name = "Ledger Stax"
        file_name = "stax.apdu"
    elif targetId == 0x33100004:
        device_name = "Ledger Nano S Plus"
        file_name = "nano_sp.apdu"
    elif targetId == 0x33000004:
        device_name = "Ledger Nano X (developer)"
        file_name = "nano_x_developer.apdu"
    elif targetId == 0x31100002:
        device_name = "Ledger Nano S <= 1.3.1"
        file_name = "nano_s.apdu"
    elif targetId == 0x31100003:
        device_name = "Ledger Nano S 1.4.x"
        file_name = "nano_s.apdu"
    elif targetId == 0x31100004:
        device_name = "Ledger Nano S >= 1.5.x"
        file_name = "nano_s.apdu"
    elif targetId == 0x31000002:
        device_name = "Ledger Blue <= 2.0"
        file_name = "ledger_blue.apdu"
    elif targetId == 0x31000004:
        device_name = "Ledger Blue 2.1.x"
        file_name = "ledger_blue.apdu"
    elif targetId == 0x31010004:
        device_name = "Ledger Blue v2 2.1.x"
        file_name = "ledger_blue.apdu"
    else:
        # If the targetId is not recognized, raise an error
        raise ValueError("Unknown Device with Target ID: 0x%x", targetId)
    
    return file_name, device_name

def press_any_key_to_exit(exitcode):
    """
    This function waits for the user to press any key before exiting the program.
    It uses the 'keyboard' library to detect key presses.
    """
    print("Press any key to exit...")
    # Wait for the user to press any key
    keyboard.read_event(suppress=True)
    sys.exit(exitcode)

def run_script():
    """
    This function performs the following tasks:
    - Connects to the Ledger device.
    - Sends a GET_VERSION command to retrieve the targetId and device information.
    - Retrieves the corresponding APDU file based on the targetId.
    - Installs the Babylon app on the Ledger device.
    - Deletes the app if it's already installed, then installs it again.
    - Waits for user input before closing the program.
    """
    try:
        # Connect to the Ledger device
        dongle = getDongle(False)  
        apdu = bytearray([0xE0, 0x01, 0, 0, 0])  # GET_VERSION command to fetch version info
        data = dongle.exchange(apdu)  # Send the command to the device and get response
        
        # Parse the targetId from the device response data (first 4 bytes)
        target_id = int.from_bytes(data[:4], byteorder='big')  # Extract target_id
        
        # Get the file name and device name based on the target_id
        fileName, device_name = get_file_name_by_target_id(target_id)
        
        # Print the device name to the console
        print(f"Device Name: {device_name}")
        
        # Open the corresponding file to get APDU commands
        with open(get_apdu_file_path(fileName), "r") as file:
            class SCP:
                def __init__(self, dongle, targetId, rootPrivateKey):
                    secret = getDeployedSecretV2(dongle, rootPrivateKey, targetId)
                    self.loader = HexLoader(dongle, 0xE0, True, secret)

                def encryptAES(self, data):
                    return self.loader.scpWrap(data)

                def decryptAES(self, data):
                    return self.loader.scpUnwrap(data)

            # Generate a private key for SCP (Secure Channel Protocol)
            privateKey = PrivateKey()
            publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
            print("Public Key: %s" % publicKey)
            rootPrivateKey = privateKey.serialize()
            
            print("Please confirm the public key shown on the device is the same as the one above to manage the app safely")
            scp = SCP(dongle, target_id, bytearray.fromhex(rootPrivateKey))

            appExists = False
            appName = "Bitcoin Test"  # TODO: Change this to the app name you want to install
            apps = scp.loader.listApp()  # List all installed apps on the device
            for app in apps:
                if app["name"] == appName:
                    appExists = True
                    break

            # If the app already exists, delete it
            if appExists:
                print("Deleting existing app, please confirm on the device")
                scp.loader.deleteApp(bytes(appName, "ascii"))
                print("App deleted")

            # Install the new app, prompting the user for confirmation on the device
            print("Installing app, please confirm on the device, and then enter the PIN code after processing finishes")
            for data in file:
                data = binascii.unhexlify(data.replace("\n", ""))
                if len(data) < 5:
                    continue

                apduData = data[5:]  # Get the APDU data part (skipping header)
                apduData = scp.encryptAES(bytes(apduData))  # Encrypt the data
                apdu = bytearray([data[0], data[1], data[2], data[3], len(apduData)]) + bytearray(apduData)
                result = dongle.exchange(apdu)  # Send APDU to the device
                result = scp.decryptAES(result)  # Decrypt the response
            print("App installed successfully")

        dongle.close()  # Close the connection to the device

    except Exception as e:
        print(f"Error occurred: {e}")  # Print the error message if an exception occurs
        press_any_key_to_exit(1)  # This will keep the window open until the user presses a key

    # Wait for the user to press any key before closing the terminal window
    press_any_key_to_exit(0)  # This will keep the window open until the user presses a key


if __name__ == "__main__":
    run_script()  # Run the script to start the app installation process

