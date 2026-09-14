brim



## Introduction 

In our environment we are going to be taking the role of a security analyst and analyzing PCAP files and their associated network alerts to get a better idea of whether we have a threat/true positive or not in our environment 


*** Unfinished Review *****


**What was the alert signature for A Network Trojan was Detected?**


to view alerts and alert signatures within PCAP files, we need to use **Brim** we can select brim and upload the PCAP file to **Brim**, after that we can see the logs in Brim's **GUI**.


<img width="845" height="684" alt="image" src="https://github.com/user-attachments/assets/aa6201b7-c65f-4ee0-abe1-e05064462431" />

Next we need to filter these logs according to the requested alert category: **A Network Trojan was detected**

We can do this via asking for all logs which the event type is "alert" and then using a pipe (|) to also request that it only have logs that the alert.category (Alert Category field) matches **"A Network Trojan was Detected"**


Altogether, our query should look like: **event_type=="alert" | alert.category=="A Network Trojan was detected"**:


<img width="845" height="690" alt="image" src="https://github.com/user-attachments/assets/8314f698-f452-4208-81c6-cd6b41564abd" />

We find a single log and need to check the signature of this event:

We can click the event and see the Brim log details:

<img width="1392" height="881" alt="image" src="https://github.com/user-attachments/assets/2e299d33-61fa-42cc-aaa1-4699a93247fa" />

In the alert.signature field we can find our answer; **ET MALWARE Likely Evil EXE download from MSXMLHTTP non-exe extension M2**


**What was the alert signature for Potential Corporate Privacy Violation?**

Here we can use the same filter as before, except changing the category to: **What was the alert signature for Potential Corporate Privacy Violation?**

and doing the same steps
