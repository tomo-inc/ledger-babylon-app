# Babylon App Installer for Ledger Devices

## Description
This script is used to install babylon app on Ledger devices.

## Prerequisites
Python: >=3.12,<3.14

## Build Steps
1. Prepare all apdu files into `./apdu` folder
   - File names are determined by `get_file_name_by_target_id` method
2. Create and activate virtual environment:
   ```bash
   python -m venv venv
   ```
3. Install required packages:
   ```bash
   pip install ledgerblue keyboard pyinstaller
   ```
4. Build executable:
   ```bash
   pyinstaller ./babyloninst.spec
   ```
5. The executable will be available at:
   ```bash
   # Windows
   dist/babyloninst.exe
   
   # macOS/Linux
   dist/babyloninst
   ```

## Run
### On Windows
Just double click.

### On MacOS
Run in the terminal with the admin privilege.
`sudo ./dist/babyloninst`


## Device Compatibility Table

| Device Name | Firmware Version | Target ID |
|-------------|-----------------|-----------|
| Flex | all | 0x33300004 |
| Stax | all | 0x33200004 |
| Nano S Plus | all | 0x33100004 |
| Nano X | developer units only* | 0x33000004 |
| Nano S | <= 1.3.1 | 0x31100002 |
| Nano S | 1.4.x | 0x31100003 |
| Nano S | >= 1.5.x | 0x31100004 |
| Ledger Blue | <= 2.0 | 0x31000002 |
| Ledger Blue | 2.1.x | 0x31000004 |
| Ledger Blue v2 | 2.1.x | 0x31010004 |

\* Note: You can only install applications on the Ledger Nano X through Ledger Live.