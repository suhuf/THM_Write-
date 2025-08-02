

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

We see here the attacker is enumerating the environment via the compromised DEAN account there is valuable info here but there is not the info we need for this question, lets try the terms server01 and server02















