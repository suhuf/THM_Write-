## Introduction

This is a **Medium** **Splunk**\-focused room that helps us get familiar with using Splunk to filter logs intelligently, view IOCs, and interact with multiple end users' and network segments' logs. This room is Host-centric.

## Scenario

<img width="1288" height="649" alt="image" src="https://github.com/user-attachments/assets/b7ee58da-ce65-4d04-8a22-c15cf6c5b691" />

For this lab, we should first open our Splunk instance, click Start machine, and then, when it is ready, click Follow browser URL (or similar):

Since we are going to be reviewing gathered and not live logs, we select **Search & Reporting** on the left:

<img width="1879" height="851" alt="image" src="https://github.com/user-attachments/assets/4c0a63e0-9c95-47b1-a301-1ebd756bceba" />

We can now see our interface for searching Splunk logs. The first thing we should do, and this is very important, is change the time range for the logs to the last 24 hours. To start, we can set it to all time and see how it goes:

<img width="1876" height="738" alt="image" src="https://github.com/user-attachments/assets/1674957d-f06c-4489-854c-c4134d1592c8" />

Next, we need to select a source to look at for logs. To test and make sure everything is working right, we can set our source to Windows event logs by choosing "win_event_logs.json".

Paste or type this into the search bar and then select the search looking glass: **source="win_event_logs.json"**.

<img width="1901" height="869" alt="image" src="https://github.com/user-attachments/assets/71ae38f4-ce3f-42f3-90ad-37150f2e0d88" />

We then should be able to see a large amount of logs available, confirming Splunk is working and reading logs correctly for our analysis.

<img width="1903" height="855" alt="image" src="https://github.com/user-attachments/assets/6f9023e1-e597-4e0a-8c76-9b2e52bd76f4" />


## Initial Compromise, Exploitation, & Escalation

**How many logs are ingested from the month of March, 2022?**

For this, we are asked for **All** logs, from all sources that are present for the date **March 2022.**

to do this we first need/should edit the source to include from all sources, this can be done via setting the source to a wildcard (\*)

<img width="1903" height="855" alt="image" src="https://github.com/user-attachments/assets/f719691e-371b-4e35-831e-b862ca047551" />

secondly, we need to also filter the logs according to both the set month and year. One way of doing this is by clicking **date_month** in the left side of the **GUI** and selecting our desired month.

<img width="889" height="553" alt="image" src="https://github.com/user-attachments/assets/647c1b29-3066-4a3e-bfa1-e4c5e34c3ebf" />

This will add our desired filter to the logs. Do the same thing for the **date_year** field and we can have both our filters enabled on our wide array of logs.

<img width="1902" height="869" alt="image" src="https://github.com/user-attachments/assets/d138156b-5b29-4f8b-bf7e-6f3fb99bb7b2" />

On the left side, **Events,** we can see the number of events (or "logs") present:

<img width="1455" height="834" alt="image" src="https://github.com/user-attachments/assets/00c3f6c7-e5ed-48ce-8eba-5aa6fea6f7c5" />

Our answer in this case should be **13959**

**Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?**

To find this, we need to see all users' names that are present in the logs. Looking at the left-hand panel can give us ideas on what filters we can use/apply to find things of substance:

When checking **Interesting Fields,** we can see a **Username** field that could be in line with what we need for this investigation:

<img width="284" height="934" alt="image" src="https://github.com/user-attachments/assets/e6dface7-36cd-430f-b75d-775975f841c3" />

If we select this and then choose **rare,** it will show all of the Usernames, with a max of 20, and then sort according to rarity:

<img width="1895" height="866" alt="image" src="https://github.com/user-attachments/assets/7a21e8a7-5194-4c1d-8969-51594be1c641" />

There is a huge red flag here in the logs, there is an account that is spoofing that it is the user "Amelia" by using a "1" instead of an "i" and they have one single event logged while the actual user has 1000+ events logged. This is a sign that something is wrong:

<img width="1889" height="814" alt="image" src="https://github.com/user-attachments/assets/0d7daa7d-14d2-4c33-ad67-a861b9c2803a" />

This is also an important example of where it is important to make sure things are being thoroughly checked and combed and not rudimentally/quickly checked as this could be easily missed without checking all usernames present.

Let's check this single log from the suspicious user as well to gain more information:

we can do this by setting our source in the search bar to wild card (\*) and setting the UserName parameter to **Amel1a** (with a 1 not an "i") and then analyzing the contents of this specific log event:

<img width="1894" height="909" alt="image" src="https://github.com/user-attachments/assets/80e10ef1-0684-4bea-96e2-3b1a7c635a2b" />

In the log, we can see that this user is using the **whoami** command to see what user they are currently logged in as and enumerating which groups they are a part of, which ties into their permissions.

This generally is not normal end-user behavior, especially in the context of this specific user spoofing an actual user and not having any other actions besides this.

This may suggest that this account was created in an attempt to create **persistence** on the system via a new user as a backdoor they can return to in the future. This is a tactic mentioned by **MITRE**

in **T1136**: <https://attack.mitre.org/tactics/TA0003/>

MITRE's list of real-world examples implementing this tactic: <https://attack.mitre.org/techniques/T1136/>

**Which user from the HR department was observed to be running scheduled tasks?**

We can filter for all logs that have the "schtasks.exe" string in them via this**:

_index=* schtasks.exe_

After this we can select the Username field and view all the users associated with these logs:

<img width="1096" height="778" alt="image" src="https://github.com/user-attachments/assets/66d6c3cf-18ed-41d7-a6fd-f87e96ad7bfb" />

We can see **Chris.fort** has a single log using this, let's click on it and investigate:

<img width="1536" height="845" alt="image" src="https://github.com/user-attachments/assets/032d6f14-2ed2-44e1-ab12-434872996434" />

We can confirm that this user is using task scheduler to run a binary **onstart**.

our answer is **Chris.fort**



\*\*Return and review \*\*

## C2 Info & Post Exploitation

**Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host.**

For this section, we are tasked with finding 3 things; breaking things down into individual attributes helps us understand how we should make our filter to find our desired answer:

1st. We need to isolate a user from the HR department.

2nd. We need to isolate them according to their use of a System process/LOLBIN.

3rd. We need to find them doing a download.

For our case, we know it will be easier to do the 1st and 3rd steps as they are straight forward.

The first case is isolating users from the HR department. When we check the host names available, we see multiple servers are named "HR_(number)". We can infer from that that these servers are multiple and that they are used by the users apart of the HR department.

Our first filter we can apply as a result is this:

<img width="770" height="317" alt="image" src="https://github.com/user-attachments/assets/1231ad2a-5ca0-4432-99c7-153db3b61337" />

_source=\* HostName="HR_\*"_

We have now narrowed our logs from 14k to around 4.5k. However, this is still too many logs. We should move to our next attribute we should filter according to:

Our 3rd attribute is the to filter downloads. We can find some downloads if we comb the logs for common domain names like .com. Let's add the string ".com" so that our filter only contains logs with this string somewhere in it:

<img width="1903" height="851" alt="image" src="https://github.com/user-attachments/assets/6645c54b-ad5b-4cdb-8748-937f15b9bd8c" />

We have now greatly reduced the "noise" and can find that only 3 events (logs) are relevant:

On the 3rd event, we see something extremely suspect:

<img width="1137" height="435" alt="image" src="https://github.com/user-attachments/assets/d65538f3-b328-4914-8cc0-55989b199f89" />

From the command line area, we can see that the user **haroon** is using a system process (LOLBin) to download contents from [controlc.com](http://controlc.com) (which is a pastebin domain) that is being saved as an .exe called **benign.**

We can also confirm this is a LOLBin, as the binary is present in **Windows\\System32.**

This LOLBin is also specifically and commonly used by threat actors to download payload stages:

**MITRE** has outlined this specific tactic here as **T1105** (Tactic):

<https://attack.mitre.org/techniques/T1105/>

**MITRE's** description of **certutil** uses and other information: <https://attack.mitre.org/software/S0160/>

Our answer here as a result is **haroon**

**To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?**

This question builds on our last one, and we correctly identified the LOLBin as **certutil.exe;** as a result, our answer should be **certutil.exe**

**What was the date that this binary was executed by the infected host? format (YYYY-MM-DD)**

This question is a bit confusing; it is however referring to the **certutil** binary, _not_ the **benign.exe** binary.

We can find the date this event happened in the EventTime section of the log/event:

<img width="1523" height="533" alt="image" src="https://github.com/user-attachments/assets/60e16e00-bf98-4798-a0b3-e72b799a6146" />

**2022-03-04** should be our answer for this question

**Which third-party site was accessed to download the malicious payload?**

We were able to highlight this earlier; it is [**controlc.com,**](http://controlc.com) which is a pastebin site.

**What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?**

We also highlighted this earlier as **benign.exe**

**The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{…}; what is that pattern?**

We can visit the site ourselves and check this since it is a lab environment:

<img width="1911" height="924" alt="image" src="https://github.com/user-attachments/assets/bfa9d8e5-fae4-4c73-9fd0-4c63b2512fd2" />

Our answer is present as _THM{KJ&\*H^B0}_

**What is the URL that the infected host connected to?**

We covered this earlier; we identified [**https://controlc.com/e4d11035**](https://controlc.com/e4d11035) as the malicious **URL.**
