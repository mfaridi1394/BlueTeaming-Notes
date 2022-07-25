# Important files to investigate

 /etc/passwd
 /etc/shadow
 /etc/group
 /etc/sudoers
 /var/run/utmp: maintains a full accounting of the current status of the system, system boot time (used by uptime), recording user logins at which terminals, logouts, system events etc.
 /var/log/wtmp: acts as a historical utmp
 /var/log/btmp: records failed login attempts
 
--------------------------------------------------------------------------------------------------------------------------------------------------------------

# Memory and processes forensics

## Live memory forensics (active)

### Analyzing proccesses running on host
We can analyze the running processes on a linux system to catch anything suspicious if the host was compromised. We can lookout for sshd processes or shell processes like bash zsh and see commands executed with the pstree and ps aux forest switch. THis way we can seperate normal and suspicious and move from there.We can conclude that process is malicious or not by its invokation command which started the process.Processes can also be started by execution of binaries, we can analyze the binaries to see if they are malicious or not.

If we have a high number of processes to examine, a good point to start at would be to analyze the processes that have interesting names like (shell, reverse, miner, etc) and processes that run with service accounts (www-data).

We can used linux builtin utilities to see process on the system

Following Command will list detailed process of all users  and also show process owner username

ps aux 

We can see process in tree format through two commands

ps aux --forest

or 

pstree

THe above tools shows processes until the secon we run the command. To see active proccesses we can use "top" command.

In the case of a suspicion of a malicious crypto mining software, we can use the “top” tool to watch the processes that are using the most CPU in real time.

Ok now we have filtered some suspicious processes, now we must investigate them in detail

In the /proc directory, there are details about processes, kernels, and the Linux system. This directory is a directory that is not actually there and is made up of virtual files. When the content of a file in the /proc directory is read, the operating system will create the content of the file and present it for you. When a new process is created, a new directory is created under the /proc directory for the process like "/proc/PID". There are virtual files with detailed information about the process under the /prod/PID directory. With the help of these files, we can get detailed information about the process. 

Some of the important files under a specific /proc/pid are

- status: Contains the status of the process, the user and group identity of the person running the process, the entire list of group memberships by the user, and the PID and PPID information.
- cmdline: Contains the command line parameters used to initiate the process. 
- environ: The environ file shows the environment variables that are in effect.
- fd: The fd file shows the file descriptors. 

For e.g cat /proc/pid/cmdline

#### Eradication of malicious processes

Kill the malicious processes usinf "kill" or "killall" command



--------------------------------------------------------------------------------------------------------------------------------------------------------------

# Investigating Endpoint 

## Investigating PostExploitation

### Finding and Analyzing suspicious files

In order to identify the files the attacker has written into the file system, a good way to start would be to examine the commonly used directories by attackers. The /tmp directory is one of the directories that must be examined during the time of the incident. The /tmp directory  or /dev/shm are commonly used directories by attackers because it is an directory that every user has authorization to read and write. In addition, the files located in the /tmp directory are deleted after a certain amount of time. Thus, a late incident response means that we lose access to the evidence. 

Another good point to start at would be to examine the directories that are open to the internet. For example, we may be able to identify the webshell files by examining the directories owned by the application for a server that serves web services(/var/www). In order to be able to identify directories that are open to the internet, we must initially need to identify these services. To identify the services open to the internet, we can get help from the netstat command. 

##### Suspicious extensions

We must identify the malicious software, webshell’s, and files that are able to be run that the attacker has written into the file system. It is easier to identify these files because they have standard file extensions. With the help of the find command below, we can identify the files with .sh, .php, .php7 and .elf extensions in the file system. Instead of finding files in whole filesystem(/) we can specify interesting directrories like /var/www etc

> find / -type f \( -iname \*.php -o -iname \*.php7 -o -iname \*.sh -o -iname \*.elf \) 2>/dev/null

#### File modification time

we can see all the files modified in a specified time, and if incident timeperiod is known we can see an overview of which were files were tampered with.

By using the find tool, we can search for the files within the file system based on modification time.  For example, with the help of the find tool below, we can list the files below the /tmp directory that have been modified between the dates of 7/25/2022 00:00:00 and 7/25/2022 23:59:00. 

find /tmp -newermt "2021-10-25 00:00:00" ! -newermt "2021-10-25 23:59:00"

Instead of determining a certain time frame, we can also filter by modification date prior to X or after X. 

find / -mtime +X
find / -mtime -X

#### File permission change date

When the ownership of a file, the directories in a file or the content of a file is changed by the attacker, the Change Date of the file changes. For various reasons, the attacker may change the authorizations and ownership of the file. With the help of the find command, we can search based on change date. 

find / -ctime +X

#### Analysing File owners

While searching suspicious files, if we know the compromised users, conducting an analysis on files owned by compromised users may help speed up investigation.By use of the find tool, we can identify all of the files owned by a certain user. For example, with the help of the command below, the files owned by the www-data user is listed under the /tmp directory. 

> find /tmp -user www-data

#### Analysing malicious files and remediation

Once we have found malicious files on the system we must analyse them either through code review or CTI products like virustotal or malware sandboxing.

In the remediation step of incident response, the modifications the attacker has made to the file system must be reverted to its normal state. The files that the attacker has written into the file system must be deleted and the files the attacker has modified must be reverted to its normal state. 

If possible, it is healthier to revert the system with a clean image or a snapshot that was taken before the cyber-attack. 





 
------------------------------------------------------------------------------------------------------------------------


## Investigating File Mounts

Attackers use the file share servers during CyberAttacks for following reasons:

- Since file share servers generally have critical data, ransomware is uploaded to these servers to block the owners’ access to important information and force them to pay a ransom. 
- By hosting the ransomware malicious software in the file share servers, to upload ransomware malicious software through the file share server from the devices that the attacker has made access to. 


One of the checks that we as a DFIR guy must do during a cyber-attack is to check whether any of the file systems that have been mounted by the compromised devices has been affected by the cyber-attack.There are no logs for mount/umount so we dont have that full visibilty edge. Sometimes we can see logs regarding mounts within the dmesg.

> dmesg | grep mount

### Analysing mounted filesystems on the host

"Findmnt" is ab uiltin utility we can use to list the file systems that have been mounted on the system.

we can also use "df" which is utility for disk based tasks we can also view mounted systems.

> df -aTh




------------------------------------------------------------------------------------------------------------------------

## Investigating Network connections and sockets

Attackers usually setup a c2 connection to c2 server. If we can identify such connections we can immediatelt reduce impact of incident and move forward with more verbose information. We can look for active sockets via linux built in utility "netstat"

> netstat -anpl

Attackers can also  change firewalls rules from iptables 

we can see all iptables rules to identify if something is out of ordinary.

> iptables -L




------------------------------------------------------------------------------------------------------------------------

## Investigating for Persistence

### User account activities

Attackers add new users and modify existing users to ensure persistence. We can read passwd file to see users present on system.

Attackers prefer names such as support, service, dev, admin and sysadmin for the users they create in order to prevent themselves from being detected. We should pay attention to users with these names. 

If the passwd file has incorrect permissions, users can be compromised by editing the passwd file. Attackers can take over users by replacing the "x" value next to their username with the password they created. For this reason, the information in the password field in the passwd file should be carefully checked during the incident response.

In addition, the shell information of the users should be checked. Shell information of users who should not have shell should be double-checked.

#### see user creation/deletion/modify related activity

If the attacker has not cleaned the auth.log file, it is possible to detect newly created users via the auth.log file.

tail /var/log/auth.log

To see new added users on system

cat /var/log/auth.log  | grep useradd

To see users who changed their password

cat /var/log/auth.log  | grep passwd


#### Identifying user groups and permissions

After identifying the users, the groups that these users are included in, and the authorizations defined specifically for these users should also be determined.

We have to examine the groups and the users included in the groups through the /etc/group file. The contents of the group file can be viewed using the cat command.

cat /etc/group

While conducting our examinations, we must pay attention to the critical groups and the users included in these groups. Users who should not be included in these groups should be identified. For example, the www-data user being included in the sudo group is certainly suspicious. Some of the critical groups are as stated below:

  -  root
  -  adm
  -  shadow
  -  sudo
  
Another file that needs to be checked in order to understand the authorizations of users or groups is “/etc/sudoers”. There is information on which users and groups can use sudo authority to what extent on this file.

cat /etc/sudoers
  
  
You can list group processes by searching for the words “groupadd” and “usermod” in the auth.log file. Listing the group changes in the date range of the attack will make it easier to track the actions taken by the attacker.

cat /var/log/auth.log | grep groupadd
  
cat /var/log/auth.log | grep usermod


#### seeing current logged in users

With the help of some tools that are installed by default in most linux systems, users with an active connection on the operating system can be listed. Its recommended installing as few new tools as possible in order to preserve the integrity of the device during the incident response procedure. 

The command last,users, who give such information and are already present in linux

  
#### Investigating ssh activities


The /var/log/auth.log file can be examined to detect users logged into the system via SSH. This file includes successful logins as well as unsuccessful logons. In this way, we can detect brute-force attacks from within the auth.log file.

You can list the failed login attempts with the following command.

cat /var/log/auth.log | grep "Failed password"

As an alternative and this will show details, failed SSH logins can be determined with the journalctl command.

journalctl _SYSTEMD_UNIT=ssh.service | egrep "Failed|Failure"
  
  
Theres no ssh group in linux like rdp group for windows so we must extensively investigate to determine users having ssh permission and see if they should have been allowed or is suspicious.Attackers sometimes add new accounts and alloww ssh for ease of access.

The following steps should be followed in order to detect users who can conduct SSH.

 1- By reading the /etc/passwd file, the users on the system are detected.
 2- Users who do not have a valid shell are removed from the list.
 3- Users who do not have valid passwords are removed from the list.
 4- Users with SSH permissions are detected in /etc/ssh/sshd_config. If "AllowUsers" is specified in this file, it means that other users cannot use the SSH service.
 
 
 
#### Eradication

we can delete any users created and files downloaded/created by attackers. we must also do a AV scan and perform a pentest on endpoint to harden the system and fix any broken permissions etc. 
 
 
 
 
 
 
 
------------------------------------------------------------------------------------------------------------------------
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
