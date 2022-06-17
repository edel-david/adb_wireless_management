import os
import string
import subprocess
from dotenv import load_dotenv
from multiprocessing import Process,Pipe
from multiprocessing.connection import Connection


def get_env_or_error(env_var_name:str):
    ret = os.getenv(env_var_name) or EnvNotFoundRaiser(env_var_name)
    ret=str(ret)
    return ret


class EnvNotFoundRaiser():
    def __init__(self,env_var_name):
        raise KeyError(F"{env_var_name} was not found in .env file or ENV Vars")


load_dotenv()

# class Buffer():
#     ip:None | str
#     def __init__(self):
#         self.ip=None




SCRCPY_PATH=os.getenv("SCRCPY_PATH")
# DEVICE_NAME=get_env_or_error("DEVICE_NAME")
DEFAULT_PHONE_IP=os.getenv("DEFAULT_PHONE_IP")



class IPNotFoundError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

def check_if_ip(possible_ip:str)->bool:
    ip_parts=possible_ip.split(".")
    try:
        [int(part) for part in ip_parts]
        if len(ip_parts)==4:
            return True
        
    except Exception as e:
        print(F"{e} happened")
    return False

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
    is_ip=check_if_ip(possible_ip)
    if is_ip==True:
        return possible_ip
    else:
        raise IPNotFoundError("")

def connect_to_wireless(ip:str,port:str | int="5555"):
    port=str(port)
    if ip is None:
        return
    ret=subprocess.run(["adb", "connect",F"{ip}:{port}"],capture_output=True)
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
    global port
    parent_con, child_con =Pipe()
    p=Process(target=launch_scrcpy_thread
    ,args=(child_con,port,*scrcpy_args)
    )
    p.start()

def launch_scrcpy_thread(con:Connection,port = 5555,*scrcpy_args):
    
    ip=get_adb_android_ip("-e") # TODO add provided arg instead of -e
    if SCRCPY_PATH is None:
        print("no SCRCPY_PATH env var found")
        return
    try:
        print("ctrl + c to end scrcpy")
        print(scrcpy_args)
        print(*scrcpy_args)
        subprocess.call([SCRCPY_PATH,F"--tcpip={ip}:{port}", *scrcpy_args], stdout=subprocess.PIPE)
        # print("started scrcpy")

    except FileNotFoundError as e:
        print(F"{e.args} {e.errno} {e.filename} {e.filename2} {e.strerror}")
    except OSError as e:
        print(F"{e.args} {e.errno} {e.filename} {e.filename2} {e.strerror}")
    except KeyboardInterrupt:
        print("ended scrcpy")

def scan_android_device_ports_for_adb_tcp(ip:str):

    ret=subprocess.run(["powershell","-command",F'nmap {ip} -p 37000-44000 | Where-Object{{$_ -match "tcp open"}} | ForEach-Object {{$_.split("/")[0]}}'],capture_output=True)
    # nmap 192.168.139.83 -p 37000-44000 | awk "/\/tcp/" | cut -d/ -f1 # get port on linux
    port=ret.stdout.decode().strip()
    return port

def connect_wireless_random_port(ip_poss_port:str|None):
    global port
    if ip_poss_port is None:
        if DEFAULT_PHONE_IP is None:
            ip=input("enter the ip of the phone(or set it as env var)")
        else:
            ip=DEFAULT_PHONE_IP
        port=scan_android_device_ports_for_adb_tcp(ip)
    elif ":" not in ip_poss_port: # should be just ip
        if check_if_ip(ip_poss_port):
            ip=ip_poss_port
            port=scan_android_device_ports_for_adb_tcp(ip_poss_port)
        else:
            raise IPNotFoundError(F"{ip_poss_port} is not a valid ip or ip:port")
    else:   # is ip:port
        ip, port= ip_poss_port.split(":")
        if check_if_ip(ip):
            connect_to_wireless(ip,port=port)
        else:
            raise IPNotFoundError(F"{ip_poss_port} is not a valid ip or ip:port")
    connect_to_wireless(ip,port)
    print("Connected?")



def main():
    global port
    try:
        p:Process
        list_devices()
        while True:
            inp=input("wlan | usb | status | scrcpy | power | connect(random port) \n>>> ")
            match inp.split(" "):
                case ["wlan"] | ["wifi"]:
                    turn_on_wlan()
                case[ "usb"] | ["stop"]:
                    stop_tcp_server()
                case ["status"] | ["devices"]:
                    list_devices()
                case ["scrcpy", *scrcpy_args]:
                    print(F" scrcpy args are: {scrcpy_args}")
                    launch_scrcpy(*scrcpy_args)
                case ["power" ,*after_power]:
                    if after_power==[] or after_power ==["button"]:
                        subprocess.run(["adb","shell","input", "keyevent","26"],check=True)
                        print("power button pressed")
                case ["connect",*ip_poss_port]:  # to connect to adb wireless if you used the android 11+ quick settings developer tile to enable wireless debug. This trash tile uses an random port, wich serves no reason known to mankind. 
                    if ip_poss_port:
                        connect_wireless_random_port(ip_poss_port[0])
                    else:
                        connect_wireless_random_port(None)
                

                    
    except KeyboardInterrupt:
        print("end")

if __name__=="__main__":
    port=5555
    main()