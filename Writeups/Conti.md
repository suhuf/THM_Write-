## **Conti Ransomware: TryHackMe Room Write-Up**

**Basic Introduction:**

This is a write-up of the **Conti** challenge on Tryhackme. **Conti** is an infamous commercialized black hat ransomware most likely of Russian origin, it is sold by RAAS (Ransomware As a service) providers and is/was one of the most popular from 2019 - 2022.

In addition to this software itself, which is attributed to multiple different APTs, there was a group called the Conti Group that also used this Ransomware in attacks.

Mitre has an entry detailing the TTPs of this RAAS here: https://attack.mitre.org/software/S0575/  

As a result of above, this room is going to be mostly post compromise Malware Analysis covering behavior, TTPs, IOCs and etc.

This challenge is focused on **Splunk** Logs.


## **SITREP**


<img width="1301" height="718" alt="image" src="https://github.com/user-attachments/assets/b9eba922-f6d3-469b-8250-e3d3eabb3607" />


Referenced link: https://www.bleepingcomputer.com/news/security/fbi-cisa-and-nsa-warn-of-escalating-conti-ransomware-attacks/


## **Exchange Server Compromised**

<img width="1304" height="888" alt="image" src="https://github.com/user-attachments/assets/d1abb5e3-0d5a-4bdf-b679-a9a6915c909d" />

**Can you identify the location of the ransomware?**


Lets take a visit to our instance of Splunk and see how many logs we are working with for this investigation:


We go to search and reporting, set the time period to all time and set the index to main:

<img width="1875" height="712" alt="image" src="https://github.com/user-attachments/assets/140cd2dd-b412-4560-ab77-28e2c1a5d8d2" />

We have nearly 30k events logged; Meaning we are going to have to be smarter about our filtering for this exercise than we were with Volt Typhoon.


When it comes to analyzing malware, an easy way to spot the source process is checking for process names, finding a strange process name/directory can be a good starting point to finding the malware's tracks. Let's select the processname field and look for what is present:


<img width="852" height="587" alt="image" src="https://github.com/user-attachments/assets/9e7853c9-52a0-445f-a307-0f95fb8e9ac0" />


Choose top values, set the top limit to 0 and then choose statistics


<img width="524" height="137" alt="image" src="https://github.com/user-attachments/assets/af66f79f-1975-48d7-a2b5-1277bf6d027c" />


We also can check our provided hint for more info:

<img width="448" height="119" alt="image" src="https://github.com/user-attachments/assets/4d2242f0-aaa1-45f8-a126-28e1f5fb139f" />






