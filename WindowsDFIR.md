#  Live Memory Analysis


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



----------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Investigating Event logs

we can use threat hunting scripts which will process event logs and enrich with known signatures to find iocs and mitre ttps. Some of good projects are

1. DeepBlueCli
2. Hayabusa




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


#### Startup Folders


To detect If any malicious files are placed in Startup folder , visit following paths

1- C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
2- C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp




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




# Windows Forensics Artifacts (timeline,evidence of execution,user activity, system activity, external devices,network artifacts)

Threat actors often abuse windows registry keys and hives to persist. We can also look at sans registry dfir cheatsheet for quick reference https://www.13cubed.com/downloads/dfir_cheat_sheet.pdf

#### System wide Registry Hives

If we are accessing a live system, we will be able to access the registry using regedit.exe, and you will be greeted with all of the standard root keys we learned about in the previous task. However, if we only have access to a disk image, we must know where the registry hives are located on the disk. The majority of these hives are located in the C:\Windows\System32\Config directory and are:

    DEFAULT (mounted on HKEY_USERS\DEFAULT)
    SAM (mounted on HKEY_LOCAL_MACHINE\SAM)
    SECURITY (mounted on HKEY_LOCAL_MACHINE\Security)
    SOFTWARE (mounted on HKEY_LOCAL_MACHINE\Software)
    SYSTEM (mounted on HKEY_LOCAL_MACHINE\System)


#### User HIves
Apart from these hives, two other hives containing user information can be found in the User profile directory. For Windows 7 and above, a user’s profile directory is located in C:\Users\<username>\ where the hives are:

    These both files are hidden

    NTUSER.DAT (mounted on HKEY_CURRENT_USER when a user logs in)  -> C:\Users\<username>\
    USRCLASS.DAT (mounted on HKEY_CURRENT_USER\Software\CLASSES)   -> C:\Users\<username>\AppData\Local\Microsoft\Windows  

#### Recently Ran programs

There is another hive called amcache hive.This hive is located in C:\Windows\AppCompat\Programs\Amcache.hve. Windows creates this hive to save information on programs that were recently run on the system. 

#### Registry logs and Backups

Some other very vital sources of forensic data are the registry transaction logs and backups. The transaction logs can be considered as the journal of the changelog of the registry hive. Windows often uses transaction logs when writing data to registry hives. This means that the transaction logs can often have the latest changes in the registry that haven't made their way to the registry hives themselves. The transaction log for each hive is stored as a .LOG file in the same directory as the hive itself. It has the same name as the registry hive, but the extension is .LOG. For example, the transaction log for the SAM hive will be located in C:\Windows\System32\Config in the filename SAM.LOG. Sometimes there can be multiple transaction logs as well. In that case, they will have .LOG1, .LOG2 etc., as their extension. It is prudent to look at the transaction logs as well when performing registry forensics.

Registry backups are the opposite of Transaction logs. These are the backups of the registry hives located in the C:\Windows\System32\Config directory. These hives are copied to the C:\Windows\System32\Config\RegBack directory every ten days. It might be an excellent place to look if you suspect that some registry keys might have been deleted/modified recently.


#### Analyzing Registry Hives

We can analyse the  registry either live on the system or by copying the hives and investigating them locally which is recommended. We can use Autoruns tool to inspect live registry or ftk registry accessor etc

##### On Live systems :
 
 In Autoruns we can use logon and explorer tabs to inspect registry. By checking the controlpath section , we can verify of a malicious file . If there are many reg values we can first analyze those keys which dont have any description or publisher information.Theres a option of hide windows entries in autoruns which is enabled by default, to see all entries unset this option.

We can also check “Event Log”s, when a registry value is changed, an “EventID 4657” log is created. We can continue your analysis by filtering the security logs. 


##### Offline investigations

Now that we have copy of registry hives from pc in investigation , we must analyze these hives from our forensics workstation. Note that autopsy and kape helps this process by automatically carving important foreniscs artifacts from registry,  but we should know how to do it manually. We can use following tool for analysing

> Zimmerman's Registry Explorer





##### Analysing registry artifacts 

1. OS version :  We must find os version of the system in investigation. This info is stored in

> SOFTWARE\Microsoft\Windows NT\CurrentVersion

2. Control Set :  The hives containing the machine’s configuration data used for controlling system startup are called Control Sets. Windows creates a volatile Control Set when the machine is live, called the CurrentControlSet (HKLM\SYSTEM\CurrentControlSet). For getting the most accurate system information, this is the hive that we will refer to. We can find out which Control Set is being used as the CurrentControlSet by looking at the following registry value:

> SYSTEM\Select\Current

Last known good config is at

> SYSTEM\Select\LastKnownGood

3. Computer Name :

> SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName 

4. TimeZone Information : For accuracy, it is important to establish what time zone the computer is located in. This will help us understand the chronology of the events as they happened

> SYSTEM\CurrentControlSet\Control\TimeZoneInformation

5. Network Information : 

> SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces

Each Interface is represented with a unique identifier (GUID) subkey, which contains values relating to the interface’s TCP/IP configuration. This key will provide us with information like IP addresses, DHCP IP address and Subnet Mask, DNS Servers, and more. This information is significant because it helps you make sure that you are performing forensics on the machine that you are supposed to perform it on.

The past networks a given machine was connected to can be found in the following locations:

> SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged

> SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed

6. AutoRun Applications

The following registry keys include information about programs or commands that run when a user logs on. 

> NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run               (user hives)

> NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce           (user hives)
 
> SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce                      (system hives)

> SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run         (system hives)

> SOFTWARE\Microsoft\Windows\CurrentVersion\Run                           (system hives)
 
7. StartUp Items

Following keys are manipulated for startup execution 

> Software\Microsoft\Windows\CurrentVersion\Explorer\UserShellFolders          (user hives)
> Software\Microsoft\Windows\CurrentVersion\Explorer\ShellFolders              (user hives)
> SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellFolders              (system hives)
> SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserShellFolders          (system hives)
> SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run              (system hives)


8. Windows Services

Attackers can manipulate services related keys to add malicious services for persistence
  
 > SYSTEM\CurrentControlSet\Services :  IN  this registry key, if the start key is set to 0x02, this means that this service will start at boot. 
 > Software\Microsoft\Windows\CurrentVersion\RunServices Once
 > Software\Microsoft\Windows\CurrentVersion\RunServices Once
 > Software\Microsoft\Windows\CurrentVersion\RunServices
 > Software\Microsoft\Windows\CurrentVersion\RunServices 

 9. User information / Security policies 

 The SAM hive contains user account information, login information, and group information. This information is mainly located in the following location:

> SAM\Domains\Account\Users

The information contained here includes the relative identifier (RID) of the user, number of times the user logged in, last login time, last failed login, last password change, password expiry, password policy and password hint, and any groups that the user is a part of.


10. Recent Files : Windows maintains a list of recently opened files for each user. As we might have seen when using Windows Explorer, it shows us a list of recently used files. This information is stored in the NTUSER hive and can be found on the following location:
 
 
 > NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

 Registry Explorer allows us to sort data contained in registry keys quickly. For example, the Recent documents tab arranges the Most Recently Used (MRU) file at the top of the list. Registry Explorer also arranges them so that the Most Recently Used (MRU) file is shown at the top of the list and the older ones later.

Another interesting piece of information in this registry key is that there are different keys with file extensions, such as .pdf, .jpg, .docx etc. These keys provide us with information about the last used files of a specific file extension. So if we are looking specifically for the last used PDF files, we can look at the following registry key:

> NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf

11. Recent Microsoft office documents : Since Majority of initial access is through phishing, Analysing microsoft office related artifacts is important as it is most used Document suite

we can look for office version at
> NTUSER.DAT\Software\Microsoft\Office\VERSION

The version number for each Microsoft Office release is different. An example registry key will look like this:

> NTUSER.DAT\Software\Microsoft\Office\15.0\Word
 
 Starting from Office 365, Microsoft now ties the location to the user's live ID. In such a scenario, the recent files can be found at the following location. 

> NTUSER.DAT\Software\Microsoft\Office\VERSION\UserMRU\LiveID_####\FileMRU

In such a scenario, the recent files can be found at the following location. This location also saves the complete path of the most recently used files.


12. ShellBags : When any user opens a folder, it opens in a specific layout. Users can change this layout according to their preferences. These layouts can be different for different folders. This information about the Windows 'shell' is stored and can identify the Most Recently Used files and folders. Since this setting is different for each user, it is located in the user hives. We can find this information on the following locations:

> USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags

> USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU

> NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU

> NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags
 
 We can use shellbag explorer for analyzing shellbags. We must point to user hives files


 13. Dialog Box MRU's :  When we open or save a file, a dialog box appears asking us where to save or open that file from. It might be noticed that once we open/save a file at a specific location, Windows remembers that location. This implies that we can find out recently used files if we get our hands on this information. We can do so by examining the following registry keys

>NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU
>NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU



14. Windows Explorer Search : Another way to identify a user's recent activity is by looking at the paths typed in the Windows Explorer address bar or searches performed using the following registry keys, respectively.

> NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
> NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery


15. UserAssist : Windows keeps track of applications launched by the user using Windows Explorer for statistical purposes in the User Assist registry keys. These keys contain information about the programs launched, the time of their launch, and the number of times they were executed. However, programs that were run using the command line can't be found in the User Assist keys. The User Assist key is present in the NTUSER hive, mapped to each user's GUID. We can find it at the following location:

> NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count


16. ShimCache : ShimCache is a mechanism used to keep track of application compatibility with the OS and tracks all applications launched on the machine. Its main purpose in Windows is to ensure backward compatibility of applications. It is also called Application Compatibility Cache (AppCompatCache). It is located in the following location in the SYSTEM hive:

> SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache

ShimCache stores file name, file size, and last modified time of the executables.

Registry Explorer, doesn't parse ShimCache data in a human-readable format, so we go to another tool called AppCompatCache Parser, also a part of Eric Zimmerman's tools. It takes the SYSTEM hive as input, parses the data, and outputs a CSV file


17. AmCache : The AmCache hive is an artifact related to ShimCache. This performs a similar function to ShimCache, and stores additional data related to program executions. This data includes execution path, installation, execution and deletion times, and SHA1 hashes of the executed programs. This hive is located in the file system at:

> C:\Windows\appcompat\Programs\Amcache.hve

Information about the last executed programs can be found at the following location in the hive:

> Amcache.hve\Root\File\{Volume GUID}\


18. Background/Desktop activity monitor : Background Activity Monitor or BAM keeps a tab on the activity of background applications. Similar Desktop Activity Moderator or DAM is a part of Microsoft Windows that optimizes the power consumption of the device. Both of these are a part of the Modern Standby system in Microsoft Windows.

In the Windows registry, the following locations contain information related to BAM and DAM. This location contains information about last run programs, their full paths, and last execution time.

> SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}

> SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}



19. External devices (usb etc)

The following locations keep track of USB keys plugged into a system. These locations store the vendor id, product id, and version of the USB device plugged in and can be used to identify unique devices. These locations also store the time the devices were plugged into the system.

> SYSTEM\CurrentControlSet\Enum\USBSTOR

> SYSTEM\CurrentControlSet\Enum\USB

Similarly, the following registry key tracks the first time the device was connected, the last time it was connected and the last time the device was removed from the system.  This is also shown in USBSTOR key

> SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####

In this key, the #### sign can be replaced by the following digits to get the required information:
Value   Information
0064    First Connection time
0066    Last Connection time
0067    Last removal time

We can find usb device name specifically by following

> SOFTWARE\Microsoft\Windows Portable Devices\Devices

We can compare the GUID we see here in this registry key and compare it with the Disk ID we see on keys mentioned in device identification to correlate the names with unique devices



20. LNK File Analysis:

> C:\username\AppData\Roaming\Microsoft\Windows\Recent

Jump Lists (like LNK files on steroids):

> C:\username\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
> C:\username\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations
LNK files are actually embedded in the database structure in AutomaticDestinations

21. Prefetcher and SuperFetch:

• Prefetcher and SuperFetch are part of Windows' memory manager
• Prefetcher is the less capable version included in Windows XP
• Prefetcher was extended by SuperFetch and ReadyBoost in Windows Vista+
• ReadyBoot replaces Prefetcher for the boot process if > 700MB RAM
• Tries to make sure often-accessed data can be read from the fast RAM instead of slow HDD
• Can speed up boot and shorten amount of time to start programs

> C:\Windows\Prefetch

filename-hash(xxxxxxxx).pf
Example: CALC.EXE-AC08706A.pf
The hash is a hash of the file’s path. In this example, CALC.EXE is located in C:\Windows\System32. If it
were copied to another location (like the Desktop) and executed, a new .pf file would be created reflecting a
hash of the new path.

> HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\MemoryManagement\PrefetchParameters

EnablePrefetcher Key:
0 = Disabled
1 = Application prefetching enabled
2 = Boot prefetching enabled (default on Windows 2003 only)
3 = Application and Boot prefetching enabled (default)
• Task Scheduler calls Windows Disk Defragmenter every three (3) days
• When idle, lists of files and directories referenced during boot process and application startups is
processed
• The processed result is stored in Layout.ini in the Prefetch directory, and is subsequently passed to
the Disk Defragmenter, instructing it to re-order those files into sequential positions on the physical
hard drive



----------------------------------------------------------------------------------------------------------------------------------------------------------------------


### Investigating files and binaries on the system left by attacker

One of the most basic methods of maintaining persistence is to leave a malicious file within the system. This malicious file left in the system may aim to steal data from the file, open a backdoor, etc.Since there are a very large number of files within the system, it is impossible to check each one. Thus, there are two methods we can use. 

#### Manual files investigation

If we know the timeframe in which the incident occurred, we can list the files that have been created/organized during this timeframe and lower the number of files to be investigated.We can list the files that need to be investigated by choosing the timeframe of the event by use of the “Date modified” section that is located in the “Search” tab in “File Explorer”. In order to proceed more quickly through the results, we can start by primarily investigating the common extensions like “.bat” and “.exe”.The difficulty of this stage is the manual execution of proceed. However, AV evasion techniques will not work here, as it will be examined with the human eye.


#### Antivirus Scans	

we can use antivirus detailed scans on endpoint to cover thw whole disk but this doesnt guranntee a result cause files and backdoors can bypass Antivirus .


----------------------------------------------------------------------------------------------------------------------------------------------------------------------



# 

 
 
 
 
 
 
 
 
 

