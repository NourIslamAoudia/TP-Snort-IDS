TP4: Snort for IDS/IPS

Part 1: Snort as an IDS

1. Installing Snort

First, I downloaded and installed Snort on my Ubuntu system. The installation was successful as shown in the screenshot.

![Installing Snort](instaling-snort.png)

2. Viewing Network Configuration

I used the ifconfig command to view my network configuration to determine the interface and IP address details needed for Snort configuration.

![Viewing Network Configuration](2.Viewing-Network-Configuration.png)

3. Configuring HOME_NET

I configured the HOME_NET value in the Snort configuration file to match my network:

Opened the snort.conf file using: sudo nano /etc/snort/snort.conf( ps :I don't have gedit and I prefer working with nano)
Modified the ipvar HOME_NET setting to match my subnet
Saved the configuration file

![Configuring HOME_NET](3.-Configuring-HOME_NET.png)

3.2. Verifying Configuration

I verified the Snort configuration was working properly by running:

sudo snort -T -i ens33 -c /etc/snort/snort.conf (ps: I was working with ubuntu desktop for ease of use so my interface was ens33).

The configuration test was successful.

![Verifying Configuration](3.2.-Verifying-Configuration.png)

4. Creating Rules

Initial verification showed 0 Snort rules were loaded. I created my first rule in the local.rules file to detect ICMP traffic:

![Creating Rules](4.-Creating-Rules.png)

![Creating Rules](4.1.-Creating-Rules.png)

alert icmp any any -> $HOME_NET any (msg:"ICMP test"; sid:1000001; classtype:icmp-event;)

I ran the Snort configuration test again to verify that the rule was loaded successfully.

![Creating Rules](4.2.-Creating-Rules.png)

5. Running Snort in IDS Mode

I started Snort in IDS mode with console alerts:

sudo snort -A console -q -c /etc/snort/snort.conf -i ens33

6. Testing ICMP Detection

I pinged my Ubuntu system from the Kali Linux VM. When returning to the Snort console, I observed multiple alerts being generated for each ICMP packet, confirming that the rule was working correctly.

![Testing ICMP Detection](6.-Testing-ICMP-Detection.png)

![Testing ICMP Detection](6.1.-Testing-ICMP-Detection.png)

7. Creating an FTP Connection Rule

I created a second rule to detect FTP connection attempts from Kali Linux:

alert tcp 192.168.x.x any -> $HOME_NET 21 (msg:"FTP connection attempt"; sid:1000002; rev:1;)

![Creating an FTP Connection Rule](7.-Creating-an-FTP-Connection-Rule.png)

![Creating an FTP Connection Rule](7.1.-Creating-an-FTP-Connection-Rule.png)

Running the ftp server for testing:

8. Running Snort with ASCII Logging

I ran Snort again with ASCII logging enabled:

sudo snort -A console -q -c /etc/snort/snort.conf -i ens33 -K ascii

![Running Snort with ASCII Logging](8.-Running-Snort-with-ASCII-Logging.png)

9. Testing FTP Connection Detection

From the Kali Linux VM, I initiated an FTP connection to my Ubuntu system. This triggered the FTP connection rule and generated alerts in the Snort console.

![Testing FTP Connection Detection](9.-Testing-FTP-Connection-Detection.png)

10. Verifying Alert Generation

The Snort console displayed alerts for the FTP connection attempts as expected, confirming that the rule was working correctly.(this is when trying from kali)

![Verifying Alert Generation](10.-Verifying-Alert-Generation.png)

![Verifying Alert Generation](10.1-Verifying-Alert-Generation.png)

This is when trying from ubuntu for checking if there are no false positives :

11. Examining Snort Logs

I used the command ls /var/log/snort to view the Snort log directory, which contained log files including:

snort.log.\* files (pcap format)
IP address directories for alerts

![Examining Snort Logs](11.-Examining-Snort-Logs.png)

sudo ls /var/log/snort/192.168.12.148/

![Examining Snort Logs-using logs](11.-Examining-Snort-Logs-using-logs.png)

![Examining Snort Logs](11Examining-Snort-Logs-11.-Examining-Snort-Logs.png.png)

I examined the contents of the alert logs using:

11.2. Analyzing Packets with Wireshark

I used Wireshark to analyze the captured packets:

sudo wireshark

I opened ftp-capture.pcap file to examine the detailed packet information.(I copied it from the log because it didt open)

![Analyzing Packets with Wireshark](11.2.-Analyzing-Packets-with-Wireshark.png)

12-14. Testing with Windows Server

I verified the IP address of my Windows Server 2012 machine and connected to its FTP server using invalid credentials, which generated an "Login or password incorrect" message.

13. Finding the ip of the windows virtual machine:

![Testing with Windows Server](12-14.-Testing-with-Windows-Server.png)

Trying to connect from ubuntu :

![Trying to connect from ubuntu](Trying-to-connect-from-ubuntu.png)

15. Creating a Failed Login Detection Rule

I created a third rule to detect failed FTP login attempts:

alert tcp $HOME_NET 21 -> any any (msg:"FTP failed login"; content:"Login or password incorrect"; sid:1000003; rev:1;)

![Creating a Failed Login Detection Rule](15.-Creating-a-Failed-Login-Detection-Rule.png)

16. Testing the Failed Login Rule

I tested the rule by attempting to connect to the FTP server with invalid credentials again. The rule successfully detected the failed login attempts and generated alerts in Snort.

![Testing the Failed Login Rule](16.-Testing-the-Failed-Login-Rule.png)

![Testing the Failed Login Rule](16.1.-Testing-the-Failed-Login-Rule.png)

This completes Part 1 of the Snort IDS/IPS lab, demonstrating basic rule creation and alert detection for ICMP and FTP traffic.

Exo2:

1. Launching msploit and running the commands and setting the payloads and hosts :

![Exo2.1](Exo2.1.png)

2. setting snort in logging mode to log every connection :

![Exo2.2](Exo2.2.png)

3.1 Running the HFS vulnerable server :

![Exo2- 3.1](Exo2--3.1.png)

3.2: running the exploit now :

![Exo2- 3.2](Exo2--3.2.png)

Snort captured all the traffic :

![Exo2- 3.3.snort captured](Exo2--3.3.snort-captured.png)

4. creating the account and running other commands :

![Exo2-4](Exo2-4.png)

5.finding the packets :

![Exo2-5png](Exo2-5png.png)

6.following TCP streams :

![Exo2-6](Exo2-6.png)

7.finding the wanted sring :

![Exo2-7](Exo2-7.png)

Exo 3 :

1. adding the new allert rule :

![exo3-1](exo3-1.png)

2. after rerunning snort with this new rule :

![exo3-2](exo3-2.png)

3. writing the new rule for the hex values :

![exo3-3](exo3-3.png)

4. writing with the new hex dump :

![exo3-4](exo3-4.png)

5. finding 2 alerts :

![exo3-5](exo3-5.png)
