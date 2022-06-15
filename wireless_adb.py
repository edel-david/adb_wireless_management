import os
import subprocess
from dotenv import load_dotenv
from multiprocessing import Process,Pipe
from multiprocessing.connection import Connection


load_dotenv()

SCRCPY_PATH=os.getenv("SCRCPY_PATH") or ""
DEVICE_NAME=os.getenv("DEVICE_NAME") or ""



class IPNotFoundError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

def get_adb_android_ip(connection_type_flag:str|None =None):
    """
    connection_type_flag is either -d for usb of -e for ip 
    Not yet:
        or -s ip:port to specif port
    """

    ip_args=["adb"]
    if connection_type_flag is not None:
        ip_args+=[connection_type_flag]
    ip_args+=["shell","ip","route"]
    ret=subprocess.run(ip_args, capture_output=True)   # only uses usb
    
    possible_ip=ret.stdout.decode().strip().split(" ")[-1]
    ip_parts=possible_ip.split(".")
    try:
        [int(part) for part in ip_parts]
        if len(ip_parts)==4:
            return possible_ip
        else:
            raise IPNotFoundError("")
    except Exception as e:
        print(F"{e} happened")
        return None

def connect_to_wireless(ip:str):
    if ip is None:
        return
    ret=subprocess.run(["adb", "connect",F"{ip}:5555"],capture_output=True)
    print(f"{ret.stdout.decode().strip()} {ret.stderr.decode().strip()}")


def stop_tcp_server():
    try:
        ret=subprocess.run(["adb","-e","usb"],capture_output=True)
        print(f"{ret.stdout.decode().strip()} {ret.stderr.decode().strip()}")
        ret=subprocess.run(["adb","disconnect"],capture_output=True)
        print(f"{ret.stdout.decode().strip()} {ret.stderr.decode().strip()}")
    except Exception as e:
        print(e)


def start_debugging_server():
    ret=subprocess.run("adb -d tcpip 5555".split(" "),capture_output=True)
    print(f"{ret.stdout.decode().strip()} {ret.stderr.decode().strip()}")

    


def turn_on_wlan():
    phone_ip=get_adb_android_ip("-d")
    start_debugging_server()
    if phone_ip is None:
        return
    connect_to_wireless(phone_ip)
    

def list_devices():
    ret=subprocess.run(["adb", "devices"],capture_output=True)
    print(ret.stdout.decode())

def launch_scrcpy(*scrcpy_args) :
    parent_con, child_con =Pipe()
    p=Process(target=launch_scrcpy_thread
    ,args=(child_con,)
    )
    p.start()

def launch_scrcpy_thread(con:Connection):
    ip=get_adb_android_ip("-e") # TODO add provided arg instead of -e
    try:
        print("ctrl + c to end scrcpy")
        subprocess.call([SCRCPY_PATH,F"--tcpip={ip}"], stdout=subprocess.PIPE)
        print("started scrcpy")

    except FileNotFoundError as e:
        print(F"{e.args} {e.errno} {e.filename} {e.filename2} {e.strerror}")
    except OSError as e:
        print(F"{e.args} {e.errno} {e.filename} {e.filename2} {e.strerror}")
    except KeyboardInterrupt:
        print("ended scrcpy")

def main():
    try:
        p:Process
        list_devices()
        while True:
            inp=input("wlan | usb | status | scrcpy >>> ")
            match inp.split(" "):
                case ["wlan"] | ["wifi"]:
                    turn_on_wlan()
                case[ "usb"] | ["stop"]:
                    stop_tcp_server()
                case ["status"] | ["devices"]:
                    list_devices()
                case ["scrcpy", *scrcpy_args]:
                    print(F" scrcpy args are: {scrcpy_args}")
                    launch_scrcpy(scrcpy_args)
                case ["power" ,*after_power]:
                    if after_power==[] or after_power ==["button"]:
                        ret=subprocess.run(["adb","shell","input", "keyevent","26"],check=True)
                        print("power button pressed")
    except KeyboardInterrupt:
        print("end")

if __name__=="__main__":
    main()