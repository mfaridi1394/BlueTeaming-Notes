#  Memory Analysis

### Live analysis (active)

 The best way to identify a malicious activity that is actively running in the system is to conduct a memory analysis. If the attacker(s) is accessing the system remotely at that moment, and if he/she is stealing data or making an interaction in any way, there is a process that is allowing this. To identify the process allowing this, a memory analysis can be conducted. 
 
 Use PROCESS HACKER TOOL , run as administrator
 
 It provides processes view,network connections which will help us find c2communication and process related to it.
 
 It is important to know what the normal statuses are while conducting a memory analysis. For example, it is normal to have a “chrome.exe” named childprocess under the “chrome.exe” process because it may create different subprocesses for different tabs.What if we saw a “powershell.exe” process that has been created under the “chrome.exe” process? We cannot react normally to a PowerShell creation under a chrome process. We must suspect an exploitation situation and examine what the PowerShell has done and what commands it invited. 
 
1- First examine all the process and sub processes related to that process. We must know which processes are normal and which are sus, like WINWORD.EXE process must not have a powershell or cmd child process this is sus. We can also see information related to a process or subprocess like the program path, command executed which invoked that process.If web browser process has a cmd or powershell process and commands executed are like systeminfo,net user , whoami etc then this is a definate IOC.We must carefully look out for all suspicous processes and investigate them further.Sometimes the process dont seem suspicious like a python process under cmd is comon,indicating a python script was ran, to conclude it as safe we must analyse that script because attackers use innocent looking scripts or executables which further invoke malicious processes. we must analyse whole process tree if a suspicious subprocess was found,for proper root cause analysis.

2-It has a network tab where we can see all active connections. From here we can catch any suspicious traffic and then map it to the process which is making the connection. Things to look for here are any uncommon ports, and checking reputation of all active ips etc.

3-We must also see digital signature status of all processes , to see whether it is verified or not. Always look into unsigned processes just to be safe.To see signature status Open the “Process” section in Process Hacker and right click on the “Name” section that is right below it and click “Choose columns”. In the window that pops up, send the “verification status” and “Verified Signer” choices to the “Active Columns” section and click OK. Thus, you will be able to view the signature status of the files relating the actively running processes and by whom it was signed


### Memory Dump analysis (passive)



----------------------------------------------------------------------------------------------------------------------------------------------------------------------



# Investigating User activity 

Tracking user activity can come in handy. We get a visual of what events occured in some specific time , which can help us because we can investigate the user activities during the time of incident, thus reducing unneccassary noise.

### LastActivityView

Sorts activities that have occurred on devices with the data it has collected from various sources. May be very beneficial when a specific time filter is applied.

### BrowsingHistoryView

Reads the history of the web search engine on the device and shows it on a single screen. May be used to determine attacks like phishing and web exploit.


----------------------------------------------------------------------------------------------------------------------------------------------------------------------



# Identifying Persistence on hacked systems



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



#### Using cli
We can use cli to see scheduled tasks, this must only be used if we only have command line access.
Run "schtasks" to see all tasks

Attackers can delete scheduled tasks after they served its purpose.We can go through event logs to see creation of tasks,updation or deletion.This gives us much more data and wider angle . To see in Event viewer go to Applications and Services Logs-Microsoft-Windows-TaskScheduler-Operational.evtx” section located in Task Scheduler. We can also see in Security logs with EventID "4698" for Schedule task creation and EventID "4702" for scheduled task update.We can also see the command ran by this task and soforth.This enables us to see even the deleted scheduled tasks which we couldnt see in above methods.


----------------------------------------------------------------------------------------------------------------------------------------------------------------------



### Services installed or updated

Attackers often setup a windows service to maintain persistence.They may use legitmiate names like “Chrome Update” in order to make it difficult to identify the service they have created or changed. In order to detect a newly created service from Event Logs, the log with ID “4697: A service was installed in the system” can be used in system logs.When analyzing a Windows device, me must examine which services have been created/changed and which systems have been stopped.

1- EventId "4697" to see newly created services in system logs.If we know the timeframe of incident it will make work easier for us.

2- Event ID "7040" to see updated services in system logs.



----------------------------------------------------------------------------------------------------------------------------------------------------------------------




### Registry Run Keys / Startup Folder

Attackers often play with the “Registry” values or leave a file in the “Startup” folder. Thus ensuring that the requested file is run when a user opens a session.This technique is more stealthy then task scheduler ands installing services  and its harder to detect too.Registry run keys are created at runtime, attackers can add their own keys which perform an attacker controlled action at startup.

To detect If any malicious files are placed in Startup folder , visit following paths

1- C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
2- C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp


To detect malicious registry key runs

The following run keys are created by default on Windows systems:

 HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
 HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
 HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
 HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce 
 
The following Registry keys can be used to set startup folder items for persistence: 
 
 HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserShellFolders
 HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellFolders
 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellFolders
 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserShellFolders 
 
 
 The following Registry keys can control automatic startup of services during boot:

 HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices Once
 HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices Once
 HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
 HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices 
 
 
 Using policy settings to specify startup programs creates corresponding values in either of two ^^ Registry keys:

 HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
 HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
 
 
#### Using Autoruns tool to inspect registry keys:
 
 By opening the “Logon” and “Explorer” tabs, we can view the registry values that we have mentioned above. By checking the “Control Path” sections, we can check to see whether there is a suspicious file or not. If there are a high number of registry values in front of us, in order to save time, we can start by examining the registry values that do not have any values in the “Description” and “Publisher” sections.Theres a option of hide windows entries in autoruns which is enabled by default, to see all entries unset this option.

We can also check “Event Log”s, when a registry value is changed, an “EventID 4657” log is created. We can continue your analysis by filtering the security logs. 


----------------------------------------------------------------------------------------------------------------------------------------------------------------------


### Investigating files and binaries on the system left by attacker

One of the most basic methods of maintaining persistence is to leave a malicious file within the system. This malicious file left in the system may aim to steal data from the file, open a backdoor, etc.Since there are a very large number of files within the system, it is impossible to check each one. Thus, there are two methods we can use. 

#### Manual files investigation

If we know the timeframe in which the incident occurred, we can list the files that have been created/organized during this timeframe and lower the number of files to be investigated.We can list the files that need to be investigated by choosing the timeframe of the event by use of the “Date modified” section that is located in the “Search” tab in “File Explorer”. In order to proceed more quickly through the results, we can start by primarily investigating the common extensions like “.bat” and “.exe”.The difficulty of this stage is the manual execution of proceed. However, AV evasion techniques will not work here, as it will be examined with the human eye.


#### Antivirus Scans	

we can use antivirus detailed scans on endpoint to cover thw whole disk but this doesnt guranntee a result cause files and backdoors can bypass Antivirus .


----------------------------------------------------------------------------------------------------------------------------------------------------------------------



# 

 
 
 
 
 
 
 
 
 

