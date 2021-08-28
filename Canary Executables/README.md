# Canary Executables
I have included a few executable files that an attacker may not be able to resist executing. These executable files are fake binaries that print the help message of the original executable file to make it seem like the file is legitimate upon execution. These executable files are meant to be uploaded to [Canary Tokens](https://www.canarytokens.org/generate) which will send you an email alert whenever the file is executed. 

### How To Set Up Your Canary Token
1. Simply go to [https://www.canarytokens.org/generate](https://www.canarytokens.org/generate)
2. Select "__Custom exe / binary__" from the dropdown menu
3. Enter the email address to send an alert notification too
4. Set a Reminder to let you know what host you are placing this file on, the name of the fake executable file. This way your alerts will tell you where and what was executed
5. Click "Generate Canary Token" to download your new decoy executable file
6. Save the file on a device. I suggest creating a new executable for each device you plan on placing this executable file on. This is to ensure you know where the file was executed from. _This is a free tool_

__Q.__ Where should I save the Canary File?
__A.__ Anywhere that makes sense to you. I have included a couple example file locations below with a note on why that location might be good.

- ```C:\Temp```                                 # Common directory for storing files an admin may want to delete later but never did
- ```C:\Windows\Temp```                         # Common directory for storing files an admin may want to delete later but never did
- ```C:\Windows\System32```                     # In your Path variable to make files easier to execute
- ```C:\Users\Public\Downloads```               # Common place for downloaded exectuables
- ```C:\Users\Administrator\Downloads```        # Common place for downloaded exectuables
- ```C:\Windows\System32\spool\drivers\color``` # Commonly used by attackers to save files under the System32 directory tree

Use PowerShell to create a fake custom save location for Microsoft Edge Temp files. 
When you click "Open" in Microsoft Edge this is where those temporaryly saved file locations are placed

```powershell
$Guid = [guid]::NewGuid()
New-Item -Path "$env:USERPROFILE\AppData\Local\Temp\MicrosoftEdgeDownloads" -Name $Guid -ItemType File -Force
```

### List of Included Fake Executables
Below is a list of the executables I have included and why an attacker might use them
1. ```accesscheck.exe``` Used for viewing permissions on files and discovering unquoted service paths
2. ```nc.exe``` and ```nc64.exe``` Used to execute bind and reverse shells or for transferring files
3. ```procdump.exe``` Used for dumping process memory which may contain clear text passwords or other info
4. ```PsExec.exe``` Used for executing commands on remote devices using SMB

If any of the above executables are run they will display the actualy executable's help message. This is done to make it seem like they are legitimate. Maybe we can trick an attacker into thinking their command line is bad or someone messed up the executables compilation.