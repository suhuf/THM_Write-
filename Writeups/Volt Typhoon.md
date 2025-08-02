

**Hello!**

This is a write-up of the Volt Typhoon challenge on Tryhackme. **Volt Typhoon** is an infamous APT assumed to be of Chinese Origin that focus on espionage, data theft, and credential exfiltration.

It has different names from multiple different threat analysis research groups and is very stealthy in their actions post foothold, using nearly entirely only LOLBins (Living off The Land binaries), such as  wmic, ntdsutil, and netsh.

Mitre has a detailed paper highlighting their TTPs, links, and other information regarding this group here: https://attack.mitre.org/groups/G1017/ . CISA also similarily has an analysis here: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a . They have successfully

breached and exploited multiple Western government instituions.


Today we are going to be doing the Splunk focused Tryhackme Challenge that uses the TTPs and the IOCs consistent with this APT based on logs of actual compromises:

**Basic Intro:**




Firstly we access the Splunk instance, I will not be going over the VPN set up process here as the machine was unaccesible except via Attackbox and etc. When reviewing for this writeup (Annoying).

The Spunk instance will be your personal target machine's IP and on port 8000.


Select search and reporting to access the logs: <img width="1883" height="824" alt="image" src="https://github.com/user-attachments/assets/41ab1db6-e771-4563-ba38-45c318db4165" />



First thing, change the time index to **All Time** the default is 24 hours, this is to make sure we are not missing any logs and have a comprehensive analysis:


<img width="708" height="565" alt="image" src="https://github.com/user-attachments/assets/a39e4ef8-c119-4905-a9a7-9e7cd2204520" />


Now in the search bar we need to select an **Index** so we can have our main source for logs, type index and select main from the drop down menu or just put Index="main" manually.

 <img width="1907" height="716" alt="image" src="https://github.com/user-attachments/assets/82f5ed71-698b-42ac-acf9-6f397d7ebfd1" />

After enabling the search with the parameters we find there are 2k logs, the logs can be filtered via the **source** and **source** type fields, this will be important for when we are answering specific questions relating to TTPs/IOCs.




**Initial Access**

We are asked to find how the threat actor gained a foothold; 

<img width="1300" height="295" alt="image" src="https://github.com/user-attachments/assets/c8fef76b-f1c9-4167-b97f-2266abe34025" />

We can check the ADSelfService Plus logs by filtering the main Index log according to the sourcetype "adss"

<img width="867" height="356" alt="image" src="https://github.com/user-attachments/assets/7aef6f5a-ef82-4508-b6c3-5b6d24ec8629" />

After applying this filter we find that we have minimized the logs from 2k to around 650, in order to minimize this further and answer the question we can filter these logs according to action_name and search for logs that contain the user string; 'dean'.


<img width="1736" height="538" alt="image" src="https://github.com/user-attachments/assets/6755523e-724b-4cad-89a9-41ce6d3b6414" />

Through this we drastically minimize the logs and are able to narrow it down to two events that occured at the same time, one being a successful change the other being the failure, and with this we have our timestamp for this action:

<img width="924" height="517" alt="image" src="https://github.com/user-attachments/assets/7a5e1e5a-9fa2-4881-b159-8798820d9756" />

Next Question:

**Shortly after Dean's account was compromised, the attacker created a new administrator account. What is the name of the new account that was created?**

This question has two hints that we can use, firstly that this action is close to the password change we just identified, and that possibly Deans' account was used to make the new account due to the wording of the question

Lets use the same filters as before except changing the action_name to what we have available to us and removing dean just to make sure: <img width="854" height="648" alt="image" src="https://github.com/user-attachments/assets/23659fa6-e0f3-4d75-aa67-d8b69f739489" />

The enrollment action name seems like an action name that could be of use to us, and the log entries for this are few, lets apply and check.


<img width="1564" height="625" alt="image" src="https://github.com/user-attachments/assets/97edcc0f-da9c-4c94-9f31-4a097795bdf8" />

When we check this we see this new user was created at the same hour that Dean's account was compromised and that this user also is an admin user that does not follow the organizations typical naming scheme, we check this and find it is correct.



**Execution:**

Now that we have passed the Initial Accces/"Foothold" stage we now are going to begin getting into the more detailed sections, the first of them being execution. We know that Volt Typhoon is a very stealthy APT. They nearly always will be using a Windows Binary in order to execute code and evade detection which is important to note when hunting for their IOCs. Here are our first questions:


<img width="1281" height="488" alt="image" src="https://github.com/user-attachments/assets/5cab1493-02d7-436a-b3df-00d517d6f86b" />

The first question we are asked is an indepth one, we need to find a specific command that is being used to enumerate two different servers, let's first reset our filters and see what parameters we have available as a source

<img width="1005" height="571" alt="image" src="https://github.com/user-attachments/assets/1d35403c-9534-432f-9994-a49cc566abc0" />

Ignoring what we already have checked, adss, we see there are a lot of logs with **wmic** and **PowerShell** but we need to narrow it down a bit more. Lets put a filter that excludes **adss** and look for a string that is relevant to the question: lets try the word drive.

<img width="1869" height="661" alt="image" src="https://github.com/user-attachments/assets/47997169-e03a-422b-bf3c-80e2af79944a" />

We see here the attacker is enumerating the environment via the compromised DEAN account, we should note that. Amongst these events there is valuable info but not what we need for this question, lets try the terms server01 and server02


<img width="1824" height="708" alt="image" src="https://github.com/user-attachments/assets/6be37dfc-b479-4619-8c09-b7e648f2cf62" />

Fortanetly, despite our filter having a wide net we only get 11 logs, we can look through these for relevant information

<img width="1644" height="444" alt="image" src="https://github.com/user-attachments/assets/7cc24a8e-095b-47e8-8fdb-71664a653d4f" />


When searching we find a single command executed via wmic, this command contains the two servers, enumeration of their drives, and is running under the comprimised DEAN account, we should check this and see if this is the answer. (Successs).


Now the next question:

**The attacker uses ntdsutil to create a copy of the AD database. After moving the file to a web server, the attacker compresses the database. What password does the attacker set on the archive?**

As expected our APT is very attached to using Living Off the Land binary techniques, since we know what binary is used in this case we should set a filter for actions executed by that binary and analyze what is found:


lets first just search for the ntdsutil string and see which logs have this name present:

Fortantely we find a single command present usig this dll:

<img width="1905" height="493" alt="image" src="https://github.com/user-attachments/assets/b24fef0a-f23a-48ae-8a60-5f7316c842fc" />

While we do not have the password or the archiving of the database yet, we do have the location to which he copied the AD database and what he copied it as: 

**C:\Windows\Temp\tmp\temp.dit**

We should use this in our next search to see his next actions:

Lets set a filter for the file temp.dit:

<img width="1902" height="605" alt="image" src="https://github.com/user-attachments/assets/4881ec34-2dcc-4aa5-83fd-e64b23d4c725" />


The first event we find we see the archiving action taking place and can see the password he has chosen:

<img width="1627" height="111" alt="image" src="https://github.com/user-attachments/assets/120792e8-037e-46da-b237-d43fdb5a1331" />



Let's put this in and check if we are correct (Success).




**Persistence**

Here we are going to analyze how Volt Typhoon likes to make a foothold, we are given a hint that this is going to be a base64 encoded webshell:


<img width="1303" height="322" alt="image" src="https://github.com/user-attachments/assets/d3ec5582-7117-4a68-bfdf-b62c832ce812" />

Now just from instincts from doing boxes myself, I autoamtically default that the webshell is going to be present in a temp directory. This is common procedure of threat actors and in pentests as it is not a strictly monitored directory. Lets filter for the temp directory:

<img width="1911" height="699" alt="image" src="https://github.com/user-attachments/assets/54068547-96a6-4fe9-9b97-c54301f84b78" />

There are 32 logs, a bit too much for our liking so we should filter it further. We can check the CommandLine field for anything interesting. 

<img width="1753" height="644" alt="image" src="https://github.com/user-attachments/assets/bee76fca-e124-442e-ba19-f90bebd09866" />


We see that echo is used in the command line once, echo is commonly used while encoding base64 payloads and it only be using once is a reason to investigate, lets set that as our command line filter with the temp string:


<img width="1900" height="717" alt="image" src="https://github.com/user-attachments/assets/f5d8ac92-6c9a-450b-a2b1-a239a1c6b934" />


Immediately we find only one event and can already tell this is most likely malicious, Powershell is running an obfuscated base64 command that is specifically being piped into **ntuser.ini**. This is another example of Volt Typhoon using the LOLBIN technique:


We can decode this payload either in terminal or by using any online base64 decoder by copying and pasting the payload.

<img width="1282" height="929" alt="image" src="https://github.com/user-attachments/assets/d6b0d8a9-0662-4096-82c3-e6dcb1af3ca5" />



After decoding we can clearly see that it is an asp webshell. Infact it actually literally has the word webshell in its title. We know this was put into the **ntuser.ini** file in the **C:\Windows\Temp\** directory so we should provide the C:\Windows\Temp\ directory as our answer (Success).


**Defense Evasion:**


















