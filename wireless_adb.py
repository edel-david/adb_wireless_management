import os
import string
import subprocess
from dotenv import load_dotenv
from multiprocessing import Process, Pipe
from multiprocessing.connection import Connection
from sys import platform


def get_env_or_error(env_var_name: str):
    ret = os.getenv(env_var_name) or EnvNotFoundRaiser(env_var_name)
    ret = str(ret)
    return ret


class EnvNotFoundRaiser:
    def __init__(self, env_var_name):
        raise KeyError(f"{env_var_name} was not found in .env file or ENV Vars")


PLATFORM = platform

load_dotenv()

# class Buffer():
#     ip:None | str
#     def __init__(self):
#         self.ip=None


SCRCPY_PATH = os.getenv("SCRCPY_PATH")
# DEVICE_NAME=get_env_or_error("DEVICE_NAME")
DEFAULT_PHONE_IP = os.getenv("DEFAULT_PHONE_IP")

# ADB GLOBAL OPTIONS -d will use the usb device and -e will use the TCP/IP device (wifi device) or an emulator (why wifi of emulator?)


class IPNotFoundError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


def check_if_ip(possible_ip: str) -> bool:
    ip_parts = possible_ip.split(".")
    try:
        [int(part) for part in ip_parts]
        if len(ip_parts) == 4:
            return True

    except Exception as e:
        print(f"{e} happened")
    return False


def get_adb_android_ip(connection_type_flag: str | None = None):
    """
    connection_type_flag is either -d for usb of -e for ip
    Not yet:
        or -s ip:port to specif port
    """

    ip_args = ["adb"]
    if connection_type_flag is not None:
        ip_args += [connection_type_flag]
    ip_args += ["shell", "ip", "route"]
    ret = subprocess.run(ip_args, capture_output=True)  # only uses usb

    possible_ip = ret.stdout.decode().strip().split(" ")[-1]
    is_ip = check_if_ip(possible_ip)
    if is_ip == True:
        return possible_ip
    else:
        raise IPNotFoundError("")


def connect_to_wireless(ip: str, port: str | int = "5555"):
    port = str(port)
    if ip is None:
        return
    ret = subprocess.run(["adb", "connect", f"{ip}:{port}"], capture_output=True)
    print(f"{ret.stdout.decode().strip()} {ret.stderr.decode().strip()}")


def stop_tcp_server():
    try:
        ret = subprocess.run(["adb", "-e", "usb"], capture_output=True)
        print(f"{ret.stdout.decode().strip()} {ret.stderr.decode().strip()}")
        ret = subprocess.run(["adb", "disconnect"], capture_output=True)
        print(f"{ret.stdout.decode().strip()} {ret.stderr.decode().strip()}")
    except Exception as e:
        print(e)


def start_debugging_server():
    ret = subprocess.run("adb -d tcpip 5555".split(" "), capture_output=True)
    print(f"{ret.stdout.decode().strip()} {ret.stderr.decode().strip()}")


def turn_on_wlan():
    phone_ip = get_adb_android_ip("-d")
    start_debugging_server()
    if phone_ip is None:
        return
    connect_to_wireless(phone_ip)


def list_devices():
    ret = subprocess.run(
        ["adb", "devices", "-l"], capture_output=True
    )  # the -l will show the devices' product name, model name and device name (and transport_id?)
    print(ret.stdout.decode())


def launch_scrcpy(*scrcpy_args):
    global port
    parent_con, child_con = Pipe()
    p = Process(target=launch_scrcpy_thread, args=(child_con, port, *scrcpy_args))
    p.start()


def launch_scrcpy_thread(con: Connection, port=5555, *scrcpy_args):

    ip = get_adb_android_ip("-e")  # TODO add provided arg instead of -e
    if SCRCPY_PATH is None:
        print("no SCRCPY_PATH env var found")
        return
    try:
        print("ctrl + c to end scrcpy")
        print(scrcpy_args)
        print(*scrcpy_args)
        subprocess.call(
            [SCRCPY_PATH, f"--tcpip={ip}:{port}", *scrcpy_args], stdout=subprocess.PIPE
        )
        # print("started scrcpy")

    except FileNotFoundError as e:
        print(f"{e.args} {e.errno} {e.filename} {e.filename2} {e.strerror}")
    except OSError as e:
        print(f"{e.args} {e.errno} {e.filename} {e.filename2} {e.strerror}")
    except KeyboardInterrupt:
        print("ended scrcpy")


def scan_android_device_ports_for_adb_tcp(ip: str):
    if PLATFORM == "darwin":
        ret = subprocess.run(["nmap", ip, "-p 37000-44000"], capture_output=True)
        stdout_str = ret.stdout.decode()
        index = stdout_str.find("/tcp open")
        port = stdout_str[index - 5 : index]
    elif PLATFORM == "win32":
        ret = subprocess.run(
            [
                "powershell",
                "-command",
                f'nmap {ip} -p 37000-44000 | Where-Object{{$_ -match "tcp open"}} | ForEach-Object {{$_.split("/")[0]}}',
            ],
            capture_output=True,
        )
        port = ret.stdout.decode().strip()
    else:
        proceed = input("LINUX is not tested, enter to skip?")  # TODO test linux ubuntu
        pass

    # nmap ip -p 37000-44000 | awk "/\/tcp/" | cut -d/ -f1 # get port on linux
    return port


def connect_wireless_random_port(ip_poss_port: str | None):
    global port
    if ip_poss_port is None:
        if DEFAULT_PHONE_IP is None:
            ip = input("enter the ip of the phone(or set it as env var)")
        else:
            ip = DEFAULT_PHONE_IP
        port = scan_android_device_ports_for_adb_tcp(ip)
    elif ":" not in ip_poss_port:  # should be just ip
        if check_if_ip(ip_poss_port):
            ip = ip_poss_port
            port = scan_android_device_ports_for_adb_tcp(ip_poss_port)
        else:
            raise IPNotFoundError(f"{ip_poss_port} is not a valid ip or ip:port")
    else:  # is ip:port
        ip, port = ip_poss_port.split(":")
        if check_if_ip(ip):
            connect_to_wireless(ip, port=port)
        else:
            raise IPNotFoundError(f"{ip_poss_port} is not a valid ip or ip:port")
    connect_to_wireless(ip, port)
    print("Connected?")


def main():
    global port

    commands_description = {
        "wifi": '"wifi" or "wlan" will attempt to turn on your wireless debugging daemon on your phone wia usb and then connect to it wirelessly.',
        "wlan": "alias for wifi",
        "stop": '"usb" or "stop" will stop the wireless debugging daemon on the phone if it was started from usb ("adb tcpip 5555" or "adbw wifi"). Unfortunately it is not easily possible to stop the daemon if started with developer quick tile or in developer options. adb usb will restart wireless debugging with a different port. (Please tell me if thats wrong!',
    }

    try:
        p: Process
        list_devices()
        while True:
            inp = input(
                "wifi | usb | status | scrcpy | power | connect(random port) \n>>> ")
            match inp.split(" "):
                # TODO adb pair command
                case ["wlan"] | ["wifi"]:
                    turn_on_wlan()
                case ["usb"] | ["stop"]:
                    stop_tcp_server()
                case ["status"] | ["devices"]:
                    list_devices()
                case ["scrcpy", *scrcpy_args]:
                    print(f" scrcpy args are: {scrcpy_args}")
                    launch_scrcpy(*scrcpy_args)
                case ["power", *after_power_args]:
                    if after_power_args == [] or after_power_args == ["button"]:
                        subprocess.run(
                            ["adb", "shell", "input", "keyevent", "26"], check=True
                        )
                        print("power button pressed")
                case [
                    "connect",
                    *ip_poss_port,
                ]:  # to connect to adb wireless if you used the android 11+ quick settings developer tile to enable wireless debuging. This trash tile uses an random port, idk why.
                    if ip_poss_port:
                        connect_wireless_random_port(ip_poss_port[0])
                    else:
                        connect_wireless_random_port(None)
                case ["help"]:
                    print("Commands: ")

                case [
                    "help",
                    *command,
                ]:  # case where you want help for a specific command
                    print("TBD")  # TODO implement
                case _:
                    print("could not identify command")
    except KeyboardInterrupt:
        print("end")


if __name__ == "__main__":
    port = 5555
    main()
