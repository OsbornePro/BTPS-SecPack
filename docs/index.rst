========================================================
Welcome to The B.T.P.S Security Package's documentation!
========================================================
* `GitHub Page <https://github.com/OsbornePro/BTPS-SecPack>`_
* `GitLab Page <https://gitlab.com/tobor88/BTPS-SecPack>`_
* `PayPal Donations <https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=AGKU5LWZA67XC&currency_code=USD&source=url>`_
* `LiberPay Donations <https://liberapay.com/tobor/donate>`_
* `Report Issues <https://osbornepro.com/schedule-or-contact>`_


**General Summary for this project can be read at** https://github.com/tobor88/BTPS-SecPack/blob/master/README.md

The Installer.ps1 script is good to go. I created a virtual environment and ran everything from scratch to ensure you get the max protection and visibility possible with the least amount of fuss. If you experience any trouble please let me know so I am aware and can fix it. If you experience any issues or need help, feel free to reach out to me. My aim is to make this as easy to get going as possible. If something is to difficult or confusing please tell me about it. rosborne@osbornepro.com I am still adding content to this site as it is fairly new.

**FEATURE COMING SOON:**

* **ELK SIEM Tool:** I am going to set up a configuration for the ELK SIEM tool. This tool is free for certain uses and offers a purchase if desired. It will include `Elasticsearch <https://www.elastic.co/elasticsearch/>`_, `Kibana <https://www.elastic.co/kibana>`_, `Logstash <https://www.elastic.co/logstash>`_, `Winlogbeat <https://www.elastic.co/beats/winlogbeat>`_, and `GeoIP <https://www.elastic.co/blog/geoip-in-the-elastic-stack>`_. The configuration is going to use the Windows Event Forwarding (WEF) configuration I cover in the `WEF Application Setup <https://btps-secpack.com/wef-application>`_. The purpose of this is to prevent the need to install agents on the devices in your environment. The free version does not offer LDAP authentication unfortunately. The configuration will use TLS certificates to encrypt communications on the local host and listen for outside connections if you decide to install other stack programs such as `APM-Server <https://www.elastic.co/apm>`_, `Heartbeat <https://www.elastic.co/beats/heartbeat>`_, or `Metricbeat <https://www.elastic.co/beats/metricbeat>`_. `Winlogbeat <https://www.elastic.co/beats/winlogbeat>`_ logs will be sent to `Logstash <https://www.elastic.co/logstash>`_ and modified to included `GeoIP <https://www.elastic.co/blog/geoip-in-the-elastic-stack>`_ tags that can be used for mapping IP addresses. Default passwords will of course also be changed. I will also create a Docker file that can be used to prevent the need for too much manual set up. When available it can be obtained from the Official OsbornePro LLC docker site: https://hub.docker.com/orgs/osbornepro
* I am **NO** longer planning on integrating the `Virus Total API <https://support.virustotal.com/hc/en-us/articles/115002100149-API>`_ for MD5 hash comparisons. This does not provide enough cost per value however I will include a script to do this in case it is valuable to your situation.


**IMPORTANT:** This **Blue Team PowerShell Security Package**, assumes that you have referenced the `Windows Event Logging Cheat Sheet <https://www.malwarearchaeology.com/cheat-sheets/>`_ for logging in your environment. Use `LOG-MD <https://www.imfsecurity.com/free>`_ or `CIS-CAT <https://www.cisecurity.org/cis-benchmarks/>`_ (an SCAP Tool) to ensure the recommended logging is configured. These logging recommendations adhere to commonly accepted guidelines in the cyber security community. Even without the use of this security application, these guidelines should be followed to better assist your organization in the event of a compromise.


**CODE CONTRIBUTIONS**
I am always open to suggestions and ideas as well as contributions if  anyone wishes to help add to this package. Credit will of course be given where credit is due. If you wish to contribute I have placed some info on that `HERE <https://github.com/tobor88/BTPS-SecPack/blob/master/CONTRIBUTING.md>`_.


**What Purpose Does This Serve?**
This repository contains a collection of PowerShell tools that can be utilized to protect and defend an environment based on the recommendations of multiple cyber security researchers at Microsoft. These tools were created with a small to medium size mostly Windows environment in mind as smaller organizations do not always have the type of funding available to overly spend on security. The goal of this project lines up with the goals of `OsbornePro LLC. <https://osbornepro.com/>`_ This exists to help add value to a smaller organization's security by creating more visibility for the IT Administrator or Security Team.

For the case of organizations with 1,000’s of devices; you may find that this entire suite does not apply to you. This has to do with how some of the discoveries operate. For example the alert I have in the `Device Discovery <https://github.com/tobor88/BTPS-SecPack/tree/master/Device%20Discovery>`_ directory relies on DHCP assigned IP addresses. All DHCP servers in an environment are queried to create a list of known MAC addresses. This information is then saved to a CSV file for reference in discovering any new devices that join a network. This file could become too large to be effective. The other alert I can see not being effective is the `"Local Port Scan Alert" <https://github.com/tobor88/BTPS-SecPack/blob/master/Local%20Port%20Scan%20Monitor/Watch-PortScan.ps1>`_. This is because if there is an over abundance of connections the script will not be able to cover all of the connections quickly enough. Other alerts in this security package are still appropriate no matter the network size as they are Event ID based typically. To begin, I suggest `Setting up WinRM over HTTPS <https://btps-secpack.com/winrm-over-https>`_ in your environment.


.. toctree::
   :maxdepth: 4
   :caption: Contents: Installer.ps1 Script

Using the Installer.ps1 File to Get Started
===========================================
I wrote the `Installer.ps1 <https://github.com/OsbornePro/BTPS-SecPack/blob/master/Installer.ps1>`_ script allow anyone to quickly and easily install as many protections as possible offered by the B.T.P.S. Security Package. Running this script requires very minimal to zero know how. You do not need to know how to download the Git repository. `Installer.ps1 <https://github.com/OsbornePro/BTPS-SecPack/blob/master/Installer.ps1>`_ will do it for you :-)

**How can i get started using the Installer.ps1 install file?**
Here is what you need to do in order to execute this file.

1. Log into your Primary Domain Controller using an account with Administrator permissions.
2. Open an Administrative PowerShell session (Windows Key + X, The press A).
3. Execute the command in step 4. This can be done by highlighting the command (starting from IEX all the way too /Installers.ps1. This command is all one line.). Right click the highlighted text and select "COPY". Then Right Click inside your PowerShell window. If this does not paste right away you can paste by doing the key combo (Ctrl + V). This command executes all the text on that webpage inside of your powershell session without downloading the file to your disk drive.
4. ``IEX (New-Object -TypeName System.Net.WebClient).downloadString('https://raw.githubusercontent.com/OsbornePro/BTPS-SecPack/master/Installer.ps1')``
5. The installation of the B.T.P.S Security Package should then start. Some Next Generation Anti-Virus providers may block script execution in this manner. If that is the case use the below method to accomplish the same task.


**IF ABOVE COMMAND METHOD DOES NOT WORK**
Some Next Generation Anti-Virus providers may block script execution in this manner. If that is the case use the below method to accomplish the same task.

1. Log into your Primary Domain Controller using an account with Administrator permissions.
2. Open an Administrative PowerShell session (Windows Key + X, The press A).
3. The command displayed in step 4 will download the script to your disk in your Downloads directory. Copy and paste the command into your admin powershell session and press ENTER to execute it.
4. ``Invoke-WebRequest -Uri "https://raw.githubusercontent.com/OsbornePro/BTPS-SecPack/master/Installer.ps1" -OutFile "$env:USERPROFILE\Downloads\Installer.ps1"``
5. Execute the command line in step 6 to ensure your Execution Policy allows the script to execute easily. Copy and paste the command into your admin powershell session and press ENTER to execute it.
6. ``Set-ExecutionPolicy RemoteSigned -Force``
7. Execute the command line in step 8 to run the script and being installation. Include the period at the beginning of the command. Copy and paste the command into your admin powershell session and press ENTER to execute it.
8. ``."$env:USERPROFILE\Downlods\Installer.ps1"``
9. The installation of the B.T.P.S. Security Package should then begin.


**OTHER DOWNLOAD FILE COMMANDS**
As an FYI there are multiple ways to download files from the PowerShell session. If ``Invoke-WebRequest`` is blocked or does not work for you try the below commands instead. Each command does the same thing in a different way and each command is one line.

* ``(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/OsbornePro/BTPS-SecPack/master/Installer.ps1', "$env:USERPROFILE\Downloads\Installer.ps1")``
* ``Start-BitsTransfer "https://raw.githubusercontent.com/OsbornePro/BTPS-SecPack/master/Installer.ps1" -Destinations "$env:USERPROFILE\Downloads\Installer.ps1"``
* ``certutil.exe -urlcache -split -f https://raw.githubusercontent.com/OsbornePro/BTPS-SecPack/master/Installer.ps1 "$env:USERPROFILE\Downloads\Installer.ps1"``
* ``bitsadmin /transfer debjob /download /priority normal https://raw.githubusercontent.com/OsbornePro/BTPS-SecPack/master/Installer.ps1" "$env:USERPROFILE\Downloads\Installer.ps1"``

Download an Instructional PDF with images and descriptions for Installer.ps1 at the below link
==============================================================================================
https://github.com/OsbornePro/Documents/raw/main/Installer.ps1%20Demo.pdf

Download an Instructional PDF with images and descriptions for installing Sysmon at the below link
==================================================================================================
https://github.com/OsbornePro/Documents/raw/main/Sysmon%20Setup-0001.pdf


`Configure WinRM over HTTPS Instructions <https://btps-secpack.com/winrm-over-https>`_


.. toctree::
   :maxdepth: 2
   :caption: Contents:


Indices and tables
==================
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
