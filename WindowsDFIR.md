#  Live Memory Analysis, network monitoring


 The best way to identify a malicious activity that is actively running in the system is to conduct a memory analysis. If the attacker(s) is accessing the system remotely at that moment, and if he/she is stealing data or making an interaction in any way, there is a process that is allowing this. To identify the process allowing this, a memory analysis can be conducted. WE can use SANS following poster https://www.sans.org/posters/hunt-evil/ as a reference when analyzing windows processes

### Using Procmon

Procmon is a sysinternal tool by microsoft. We can use procmon to see list of active processes, processes history (not currently active) and file system monitoring. Procmon must be setup at each endpoint for continous monitoring and this can help us during our investigation as we can construct process timeline with it. Its file monitoring also shows current and recently interacted files their path , user which accessed it and time etc. Attackers or malware interact with files one way or another on disk so we can also look for suspicious files using procmon

Sysmon is advanced form of procmon which allows the procmon and additonal functionality to be integrated with windows event so its more better since we can get siem alerts via sysmon.For e.g if a process has been created via remote thread (process injection etc) which is common in malware's, a windows event is generated which we can get in out siem alerts.

### Using ProcessHacker
 Use PROCESS HACKER TOOL , run as administrator
 
 It provides processes view,network connections which will help us find c2communication and process related to it.
 
 It is important to know what the normal statuses are while conducting a memory analysis. For example, it is normal to have a “chrome.exe” named childprocess under the “chrome.exe” process because it may create different subprocesses for different tabs.What if we saw a “powershell.exe” process that has been created under the “chrome.exe” process? We cannot react normally to a PowerShell creation under a chrome process. We must suspect an exploitation situation and examine what the PowerShell has done and what commands it invited. 
 
1- First examine all the process and sub processes related to that process. We must know which processes are normal and which are sus, like WINWORD.EXE process must not have a powershell or cmd child process this is sus. We can also see information related to a process or subprocess like the program path, command executed which invoked that process.If web browser process has a cmd or powershell process and commands executed are like systeminfo,net user , whoami etc then this is a definate IOC.We must carefully look out for all suspicous processes and investigate them further.Sometimes the process dont seem suspicious like a python process under cmd is comon,indicating a python script was ran, to conclude it as safe we must analyse that script because attackers use innocent looking scripts or executables which further invoke malicious processes. we must analyse whole process tree if a suspicious subprocess was found,for proper root cause analysis.

2-It has a network tab where we can see all active connections. From here we can catch any suspicious traffic and then map it to the process which is making the connection. Things to look for here are any uncommon ports, and checking reputation of all active ips etc.

3-We must also see digital signature status of all processes , to see whether it is verified or not. Always look into unsigned processes just to be safe.To see signature status Open the “Process” section in Process Hacker and right click on the “Name” section that is right below it and click “Choose columns”. In the window that pops up, send the “verification status” and “Verified Signer” choices to the “Active Columns” section and click OK. Thus, you will be able to view the signature status of the files relating the actively running processes and by whom it was signed






----------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Automated forensics artifacts collection 


We can automate the whole process using tools like autopsy,kape etc. We can either run these tools directly on suspected host or we can create their disk image and then analys in our workstation. TO know what to look for reference the manual dfir process in next section down below

### FTK imager 
We can collect only relative artifacts(file,hives,directories) using ftkimager custom image . This way we dont need full disk to be imaged, we can only select selective  thigns which are required.

### Kape
 Kape has cli and gui interfaces. It has modules and targets files installed with it.Targets are type of artifacts and Modules are Eric zimmermen tools to analyse the artifacts with its relative tools.We can manually analyse using EZ tools but its nice to have integrated with KAPE. We can select selective targers or all targets and modules


----------------------------------------------------------------------------------------------------------------------------------------------------------------------




----------------------------------------------------------------------------------------------------------------------------------------------------------------------



## Investigating User activity 

Tracking user activity can come in handy. We get a visual of what events occured in some specific time , which can help us because we can investigate the user activities during the time of incident, thus reducing unneccassary noise.

### LastActivityView

Sorts activities that have occurred on devices with the data it has collected from various sources. May be very beneficial when a specific time filter is applied.

### BrowsingHistoryView

Reads the history of the web search engine on the device and shows it on a single screen. May be used to determine attacks like phishing and web exploit.


----------------------------------------------------------------------------------------------------------------------------------------------------------------------



## Identifying Persistence and post exploitation on hacked systems



### New users created and added to high privilege groups

During an incident response procedure, there are 2 things that we must quickly evaluate.

1-Is there currently a user in the system that should not be there?

2-Has a user created during the attack and deleted after that?


One of the common thing attackers do after compromising a system is creating a new user with unsuspicious usernames so they can login whenever they want. Attackers use names like sysadmin,supportuser ,support etc to blend in .

There are two methods to go forward with this.

1- If the newly created user still exists, we can see it with "net user" command . To see details we sue net user <username>. We can match the user created time,last logon,Password set time with the time of incident to verify that this is a persistence user and not a legitimate one. We can also see user management by entering "lusrmgr.msc" in run console. When a suspicious user is concluded then we can follow the trail of that user to move forward with the investigation.We must also track the activity of the user which created the new user since that legitimiate account was compromised by attacker so we treat it as hostile. 

2- Attackers also could have created a user in past and deleted it before we investigated.In that case we could not detect that with above approach. We can track deleted and past history through windows event logs. Open event viewer and go to windows security log. We can filter the log timeline with time of incident to minimise the log noise. Also EventID "4720" is created when a new local user is created. EventID "4732" is created when a user is added to a security group like administrator group etc. Attackers add created users to admin groups to achieve high privileges.


----------------------------------------------------------------------------------------------------------------------------------------------------------------------


### Autorun applications and Task Scheduler.

One of the most used persistence methods is to create scheduled tasks. Most malicious things from viruses to ransomware use scheduled tasks to maintain persistence.The attacker, by using scheduled tasks, ensures that the malicious file runs at regular intervals. Thus, the attacker ensures that the commands he/she wants to run are run actively and regularly.There are many methods to detect scheduled task,startup runs and registry autoruns.

WE must see all active scheduled tasks and past event logs related to scheduled tasks to see the full picture.



#### Using Autoruns tool (RUN AS ADMINISTRATOR)
This tool is part of sysinternals by microsoft. We can view all scheduled tasks on the host machine along with the the details like description of the applications, publisher name, timestamps and full path of the file which is scheduled to execute.Windows has many scheduled tasks of it own like windows defender etc so we can have unneccassary tasks which generate unneccasary cluster making it timetaking task. We must first analyze those tasks which have no publisher , as theres a good chance that a custom script or application created by user is scheduled to run.We must analyze the file from the path of scheduled task.



#### Using windows task scheduler
we can also use windows own task scheduler application to see all scheduled task.This also works same as autoruns but autoruns shows information in single window in cleaner way.


#### Startup Folders


To detect If any malicious files are placed in Startup folder , visit following paths

1- C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
2- C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp




#### Using cli
We can use cli to see scheduled tasks, this must only be used if we only have command line access.
Run "schtasks" to see all tasks

Attackers can delete scheduled tasks after they served its purpose.We can go through event logs to see creation of tasks,updation or deletion.This gives us much more data and wider angle . To see in Event viewer go to Applications and Services Logs-Microsoft-Windows-TaskScheduler-Operational.evtx” section located in Task Scheduler. We can also see in Security logs with EventID "4698" for Schedule task creation and EventID "4702" for scheduled task update.We can also see the command ran by this task and soforth.This enables us to see even the deleted scheduled tasks which we couldnt see in above methods.



### Services installed or updated

Attackers often setup a windows service to maintain persistence.They may use legitmiate names like “Chrome Update” in order to make it difficult to identify the service they have created or changed. In order to detect a newly created service from Event Logs, the log with ID “4697: A service was installed in the system” can be used in system logs.When analyzing a Windows device, me must examine which services have been created/changed and which systems have been stopped.

1- EventId "4697" to see newly created services in system logs.If we know the timeframe of incident it will make work easier for us.

2- Event ID "7040" to see updated services in system logs.



----------------------------------------------------------------------------------------------------------------------------------------------------------------------



### Investigating Event logs

we can use threat hunting scripts which will process event logs and enrich with known signatures to find iocs and mitre ttps. Some of good projects are

1. APT hunter
2. ThreatHound
3. DeepBlueCli
4. Hayabusa
5. chainsaw


### Detecting Credentials Dumping (lsass and ntds.dit)

Ntds.dit file mostly resides on Windows active directory environments

If attacker manages to dump this and lsass then attackers can get plaintext credentials both local and domain wide creds

Attackers can dump ntds.dit by using lolbins such as ntdsutil.

A thing to note is that whenever ntds.dit is dumped, a backup copy is made which is then dumped

It creates events in event logs

> Event IDs 103 and 327

- A thing to be aware is that active directory automatically occasionaly makes the copies of ntds.dit for backup and cache purposes. It mostly shows backup location of those backups so we must always be aware of this to avoid false positives. If we know the timeframe of incident , we must see those event ids in that timeframe and additonaly we can look for evidence of execution for dumping tools like mimikatz or ntdsutil tool

### Investigating files and binaries on the system left by attacker

One of the most basic methods of maintaining persistence is to leave a malicious file within the system. This malicious file left in the system may aim to steal data from the file, open a backdoor, etc.Since there are a very large number of files within the system, it is impossible to check each one. Thus, there are two methods we can use. 

#### Manual files investigation

If we know the timeframe in which the incident occurred, we can list the files that have been created/organized during this timeframe and lower the number of files to be investigated.We can list the files that need to be investigated by choosing the timeframe of the event by use of the “Date modified” section that is located in the “Search” tab in “File Explorer”. In order to proceed more quickly through the results, we can start by primarily investigating the common extensions like “.bat” and “.exe”.The difficulty of this stage is the manual execution of proceed. However, AV evasion techniques will not work here, as it will be examined with the human eye.


#### Antivirus Scans	

we can use antivirus detailed scans on endpoint to cover thw whole disk but this doesnt guranntee a result cause files and backdoors can bypass Antivirus .


----------------------------------------------------------------------------------------------------------------------------------------------------------------------



## Detecting Lateral movement (impacket artifacts)

####ATEXEC.PY
 
atexec.py domain/username:password@[hostname | IP] command
• Requires a command to execute; shell not available
• Creates and subsequently deletes a Scheduled Task with a random 8-character mixed-case alpha string
• Runs cmd.exe with arguments of "/C" followed by the command specified by the user, followed by
"C:\Windows\Temp\xxxxxxxx.tmp 2>&1"
o Where "xxxxxxxx" is the SAME random 8-character mixed-case alpha string used for the
Scheduled Task name
• Subsequently deletes the .tmp file containing command output from C:\Windows\Temp
• NOT detected and blocked by Windows Defender by default
Windows Event Log Residue:
• Two rounds of:
o Event ID 4776 in Security on target (for user specified in command)
o Event ID 4672 in Security on target (for user specified in command)
o Event ID 4624 Type 3 in Security on target (for user specified in command)
• [IF ENABLED] Event ID 4698 in Security on target
• Event ID 106, 325, 129, 100, 200, 110, 141, 111, 201, 102 in Microsoft-Windows-TaskScheduler/Operational
on target
• [IF ENABLED] Event ID 4688 in Security on target:
o svchost.exe → cmd.exe /C command > C:\Windows\Temp\xxxxxxxx.tmp 2>&1
• [IF ENABLED] Event ID 4688 in Security on target:
o cmd.exe → conhost.exe 0xffffffff -ForceV1
• [IF ENABLED] Event ID 4699 in Security on target
• [IF ENABLED AND EXTERNAL BINARY IS CALLED] Event ID 4688 in Security on target:
o cmd.exe → xxx.exe (the command specified via atexec.py)
• Two rounds of:
o Event ID 4634 Type 3 in Security on target (for user specified in command)
• [IF EXTERNAL BINARY IS CALLED, 201/102 MAY APPEAR LATER] Event ID 201, 102 in Microsoft-Windows-
TaskScheduler/Operational on target

####DCOMEXEC.PY
 
dcomexec.py -object [ShellWindows | ShellBrowserWindow | MMC20]
domain/username:password@[hostname | IP] command
• Can specify a command to run, or leave blank for shell
• Executes a semi-interactive shell using DCOM objects
• Must specify 'ShellWindows', 'ShellBrowserWindow', 'MMC20' via the -object parameter
• Uses first 5 digits of UNIX Epoch Time in commands
• NOT detected and blocked by Windows Defender by default
Windows Event Log Residue:
• Two rounds of:
o Event ID 4776 in Security on target (for user specified in command)
o Event ID 4672 in Security on target (for user specified in command)
o Event ID 4624 Type 3 in Security on target (for user specified in command)
• [IF ENABLED] Event ID 4688 in Security on target:
o svchost.exe → mmc.exe -Embedding
• Event ID 4776 in Security on target (for user specified in command)
• Event ID 4672 in Security on target (for user specified in command)
• Event ID 4624 Type 3 in Security on target (for user specified in command)
• Always present:
o [IF ENABLED] Event ID 4688 in Security on target:
mmc.exe → cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__sssss 2>&1
(where “s” is the first 5 digits of the UNIX Epoch Time at which the command ran)
o [IF ENABLED] Event ID 4688 in Security on target:
cmd.exe → conhost.exe 0xffffffff -ForceV1
o [IF ENABLED] Event ID 4688 in Security on target:
mmc.exe → cmd.exe /Q /c cd 1> \\127.0.0.1\ADMIN$\__sssss 2>&1
o [IF ENABLED] Event ID 4688 in Security on target:
cmd.exe → conhost.exe 0xffffffff -ForceV1
• User specified commands:
o [IF ENABLED] Event ID 4688 in Security on target:
mmc.exe → cmd.exe /Q /c command 1> \\127.0.0.1\ADMIN$\__sssss 2>&1
o [IF ENABLED] Event ID 4688 in Security on target:
cmd.exe → conhost.exe 0xffffffff -ForceV1
• Two rounds of:
o Event ID 4634 Type 3 in Security on target (for user specified in command)

####PSEXEC.PY
 
psexec.py domain/username:password@[hostname | IP] command
• Can specify a command to run, or leave blank for shell
• PSEXEC like functionality example using RemComSvc
• Creates and subsequently deletes a Windows Service with a random 4-character mixed-case alpha
name referencing an 8-character mixed-case alpha .exe file in %systemroot%
• Detected and blocked by Windows Defender by default
Windows Event Log Residue:
• Event ID 4776 in Security on target (for user specified in command)
• Event ID 4672 in Security on target (for user specified in command)
• Event ID 4624 Type 3 in Security on target (for user specified in command)
• Event ID 7045 in System on target (service installation: 4-character mixed-case alpha name referencing an
8-character mixed-case alpha .exe file):
o %systemroot%\xxxxxxxx.exe
• Event ID 7036 in System on target
• Event ID 7036 in System on target
• [IF ENABLED] Event ID 4688 in Security on target:
o services.exe → C:\Windows\xxxxxxxx.exe
• Event ID 4776 in Security on target (for user specified in command)
• Event ID 4672 in Security on target (for user specified in command)
• Event ID 4624 Type 3 in Security on target (for user specified in command)
• Event ID 4776 in Security on target (for user specified in command)
• Event ID 4672 in Security on target (for user specified in command)
• Event ID 4624 Type 3 in Security on target (for user specified in command)
• Event ID 4776 in Security on target (for user specified in command)
• Event ID 4672 in Security on target (for user specified in command)
• Event ID 4624 Type 3 in Security on target (for user specified in command)
• [IF ENABLED] Event ID 4688 in Security on target:
o C:\Windows\xxxxxxxx.exe → command
• [IF ENABLED] Event ID 4688 in Security on target:
o cmd.exe → conhost.exe 0xffffffff -ForceV1
• ... numerous other 4624,4634,4672 events

####SMBEXEC.PY
 
smbexec.py domain/username:password@[hostname | IP]
• No option to specify a command to run; you only get shell
• Creates and subsequently deletes a Windows Service named "BTOBTO" referencing execute.bat
for EVERY command entered into the shell
• Detected and blocked by Windows Defender by default
Windows Event Log Residue:
• Event ID 4776 in Security on target (for user specified in command)
• Event ID 4672 in Security on target (for user specified in command)
• Event ID 4624 Type 3 in Security on target (for user specified in command)
• Event ID 7045 in System on target (service installation: “BTOBTO” is the default name, but can be changed
when running smbexec.py):
o %COMSPEC% /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 >
%TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del
%TEMP%\execute.bat
• Always present:
o [IF ENABLED] Event ID 4688 in Security on target:
services.exe → cmd.exe /Q /c echo cd ^> \\127.0.0.1\C$\__output
2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q
/c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat
o [IF ENABLED] Event ID 4688 in Security on target:
cmd.exe → cmd.exe /Q /c C:\Windows\TEMP\execute.bat
o [IF ENABLED] Event ID 4688 in Security on target:
cmd.exe → conhost.exe 0xffffffff -ForceV1
• Present if commands are issued in lieu of an interactive shell:
o [IF ENABLED] Event ID 4688 in Security on target:
cmd.exe /Q /c echo command ^> \\127.0.0.1\C$\__output 2^>^&1 >
C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c
C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat
o [IF ENABLED] Event ID 4688 in Security on target:
cmd.exe → cmd.exe /Q /c C:\Windows\TEMP\execute.bat
o [IF ENABLED] Event ID 4688 in Security on target:
cmd.exe → conhost.exe 0xffffffff -ForceV1)
• If interactive shell is used, when shell exits:
o Event ID 4634 Type 3 in Security on target (for user specified in command)

####WMIEXEC.PY
 
wmiexec.py domain/username:password@[hostname | IP] command
• Can specify a command to run, or leave blank for shell
• Executes a semi-interactive shell using Windows Management Instrumentation
• Uses UNIX Epoch Time in commands
• NOT detected and blocked by Windows Defender by default
Windows Event Log Residue:
• Multiple rounds of:
o Event ID 4776 in Security on target (for user specified in command)
o Event ID 4672 in Security on target (for user specified in command)
o Event ID 4624 Type 3 in Security on target (for user specified in command)
• Always present:
o [IF ENABLED] Event ID 4688 in Security on target:
wmiprvse.exe → cmd.exe /Q /c cd \ 1>
\\127.0.0.1\ADMIN$\__ssssssssss.sssssss 2>&1)
(where “s” is the UNIX Epoch Time at which the command ran)
o [IF ENABLED] Event ID 4688 in Security on target:
cmd.exe → conhost.exe 0xffffffff -ForceV1
• [IF ENABLED] Event ID 4688 in Security on target:
o wmiprvse.exe → cmd.exe /Q /c cd 1>
\\127.0.0.1\ADMIN$\__ssssssssss.sssssss 2>&1
• [IF ENABLED] Event ID 4688 in Security on target:
o cmd.exe → conhost.exe 0xffffffff -ForceV1
• [IF ENABLED] Event ID 4688 in Security on target:
o wmiprvse.exe → cmd.exe /Q /c command 1> \\127.0.0.1\ADMIN$\__
ssssssssss.sssssss 2>&1)
• [IF ENABLED] Event ID 4688 in Security on target:
o cmd.exe → conhost.exe 0xffffffff -ForceV1
• Event ID 4634 Type 3 in Security on target (for user specified in command)
• [MAY BE PRESENT] Event ID 5857/5858 in Microsoft-Windows-WMI-Activity\Operational on targ

 
 
 # Hayabus- Event log hunting

### Command line to use
This would generate a csv timeline and an html summary report. Remember to start with core rules then core + and so on in order to widen threat hunt scope. Also use -U flag for utc, try without multiline(-M) as it adds more context. You can use -l if doing live analysis. -p flag is for profile, default is standard but make it verbose if detailed hunt is to be done
-  hayabusa-2.10.1-win-x64.exe csv-timeline -d "C:\Users\CyberJunkie\Desktop\LogJammer\Event-Logs" --output test.csv -H test.html -U

Hayabusa also has filters like timestamp filter which we can use to state from when to when analyse the logs based on timestamps. this makes faster prorcesssing and focused analysis. We also have computer name filters which are helpful when we have event logs from many different computers. we can use computer-metrics instead of csv timeline command when starting such an analysis.

Takajo can be used to extract some data like pwsh scrptblocks domains ips hashes lookup via VT from results of hayabusa(Optional,although i prefer manual analsysis of hayabusa results)
We can then use chainsaw to validate further or use evtxecmd(preferred) for more thorough analysis
https://www.youtube.com/watch?v=HXNAnxADRGE&t=1365s
 
 
 
 
 
 

