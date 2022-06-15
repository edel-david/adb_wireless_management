import os
import subprocess
import dotenv
SCRCPY_PATH=os.getenv("SCRCPY_PATH")
DEVICE_NAME=os.getenv("DEVICE_NAME")



class IPNotFoundError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

def get_adb_android_ip(connection_type_flag:str):
    """
    connection_type_flag is either -d for usb of -e for ip 
    Not yet:
        or -s ip:port to specif port
    """

    ip_args=["adb"]+[connection_type_flag]+["shell","ip","route"]
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

def launch_scrcpy():
    ip=get_adb_android_ip("-e")
    subprocess.call([SCRCPY_PATH,F"--tcpip={ip}:5555"], stdout=subprocess.PIPE)  
    # type: ignore

def main():
    try:
        list_devices()
        while True:
            inp=input("wlan | usb | status | scrcpy >>> ")
            match inp:
                case "wlan" | "wifi":
                    turn_on_wlan()
                case "usb" | "stop":
                    stop_tcp_server()
                case "status" | "devices":
                    list_devices()
                case "scrcpy":
                    launch_scrcpy()
    except KeyboardInterrupt:
        print("end")

if __name__=="__main__":
    main()