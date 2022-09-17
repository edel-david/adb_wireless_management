# ADB WIRELESS MANAGEMENT

manage your android devices tcp/adb/debugging server

## Usage



Dependencies:
- adb (the **A**ndroid **D**ebug **B**ridge is part of the android sdk) [Link to ADB](https://developer.android.com/studio/command-line/adb)
- _python-dotenv_ python package (install with pip install python-dotenv)
- nmap for port discovery for wireless debugging on random ports.
- For scrcpy: *.env* File containing:
    ```.env
    SCRCPY_PATH="C:\\Users\\$User\\Downloads\\scrcpy-win64-v1.21\\scrcpy.exe"
    DEVICE_NAME="4difu45"  (obvously use your device name and path here) 
    DEFAULT_PHONE_IP=
    ```
    (obvously use your device name and path here):

get your device name by typing _adb devices_ or type __status__ as your argument after starting this script 

___
start python script with
```
python wireless_adb.py
```

