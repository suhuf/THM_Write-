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

<img width="842" height="680" alt="image" src="https://github.com/user-attachments/assets/e8ac1b08-5de2-405e-9389-5face78add32" />

<img width="998" height="818" alt="image" src="https://github.com/user-attachments/assets/e61bbd30-b099-4100-b803-fba847c64e0e" />

Our signature answer in this case is: **ET POLICY PE EXE or DLL Windows file download HTTP**


**What was the IP to trigger either alert? Enter your answer in a defanged format.**

We can look back at the earlier log details panel and find the requested IP in the **src_ip** field 

<img width="1372" height="802" alt="image" src="https://github.com/user-attachments/assets/e0ecb265-5171-4325-96a9-a3587d1b3067" />

our IP answer is 185[.]118[.]164[.]8 (Defanged) 

*Note that it was requested that our answer be "Defanged" and I have provided the answer in _Defanged_ form. Defanging is when a malicous link or IP address is provided in a safer format that does not lead to detonation (exaggrative

wording but basically clicking the IP or link by accident and then risking compromise). This is done via adding brackets '[]' around the periods in an IP or URL.
 


**Provide the full URI for the malicious downloaded file. In your answer, defang the URI.**

We have already identified the alert log in Brim, from the Brim log details we can also follow the exact packet in **Wireshark** and then follow the stream and gain all of the information regarding this specific interaction.


We need to go to our first log associated with the **"Likely Evil EXE"** alert and click on this icon:

<img width="705" height="641" alt="image" src="https://github.com/user-attachments/assets/8cc49628-2d9b-41d4-b029-721ef43b64f1" />

Following this **Wireshark** will be opened and will highlight the associated packet:

<img width="746" height="462" alt="image" src="https://github.com/user-attachments/assets/7f271284-8400-482c-8ef0-94f9a243fe83" />

We need to find the download and its detailed information, to do this we right click on the packet, hover on follow, and the select **TCP Stream**

<img width="1017" height="636" alt="image" src="https://github.com/user-attachments/assets/c3a5b30d-da4d-4ca1-8e83-6506911b37cf" />

<img width="642" height="634" alt="image" src="https://github.com/user-attachments/assets/fcf44f80-bd51-447c-b809-2a603d956b1e" />

We can now see the details we were in need of in the TCP Stream

<img width="639" height="623" alt="image" src="https://github.com/user-attachments/assets/80cbd46b-d7f5-451c-9373-c6e8e7a7034b" />

in the **Host** area we can see the **Host** domain that is associated with the URL the user took the download from:

**awh93dhkylps5ulnq-be[.]com**

In the **GET** setion we can also see the exact page they requested from the domain, meaning the last part of the URL:

**/czwih/fxla[.]php?l=gap1[.]cab**

With this we can make out the full URL to be: **awh93dhkylps5ulnq-be[.]com/czwih/fxla[.]php?l=gap1[.]cab**  

We can provide this as our answer, make sure the answer is defanged as above.


**What is the name of the payload within the cab file?** 

For this question there are quite a few routes we could take, so let's check the hint to get a better idea of what exactly we are supposed to find here:


<img width="354" height="214" alt="image" src="https://github.com/user-attachments/assets/b43bcc27-214d-4d99-99c4-9b7cf71f08f1" />

Let's do this and see what we can find, it is always a good idea to refer back to already documented specimens when trying to identify a threat.

We can do this by moving back to **WireShark** and checking the file tab,

We then select "**Export**" and choose export objects, we then select HTTP and choose an appropriate directory to export to, we should take note of this as we will need to access this directory in the near future

<img width="486" height="515" alt="image" src="https://github.com/user-attachments/assets/301253a6-95d5-4812-84c9-a272a2a1ba33" />


Now we need to take the hash of the file, we can open a terminal session and move to the respective directory. In my case it is in downloads and I have renamed the file to "**dragon.cab**" so it is easier to interact with without all of the special characters.

we now use this command:  **md5sum <file name>** and copy the hash we are given

<img width="725" height="486" alt="image" src="https://github.com/user-attachments/assets/dde110e0-685d-47a3-90ae-68d3b272a028" />

And we now search for virus total and see what results we get when we put the MD5Hash in the searchbar:

<img width="1863" height="890" alt="image" src="https://github.com/user-attachments/assets/fa33848a-fd44-4f2f-ae3d-d6e1b12bf62f" />

We can see that the file is really a DLL, the payload is identified as draw.dll, and over 55 vendors view this as malicious.

We should provide **draw.dll** as our answer.

**What is the user-agent associated with this network traffic?**

Now we need to go back to the **TCP stream** page/panel and take note of what the user agent was within the **TCP stream** for the packet that caused the initial alert:

Again we select packet, right click, and do follow TCP stream:

<img width="888" height="831" alt="image" src="https://github.com/user-attachments/assets/74edea25-9387-4a93-970c-e91c467a7b66" />

This entire string; **Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/8.0; .NET4.0C; .NET4.0E)**

is our answer for the **user-agent**.


**What other domains do you see in the network traffic that are labelled as malicious by VirusTotal? Enter the domains defanged and in alphabetical order. (format: domain[.]zzz,domain[.]zzz)**


For this, we should move back brim, lets reset our work we did in brim and return to the base .pcap file in brim, Now lets set a filter that does these 3 things:


Sorts all DNS records

Narrows down the response and the result by choosing to display only one of these 2 things,

sort the results

then only include unique results.

We can do this via this one liner:

**dns | cut query | sort | uniq**

we now find these results through all of our logs:

<img width="1416" height="671" alt="image" src="https://github.com/user-attachments/assets/4e5b2105-76ee-48e9-b588-bb6c3df1459e" />

<img width="1420" height="626" alt="image" src="https://github.com/user-attachments/assets/101787e2-341a-42e7-b12c-0f7b5f6c61da" />



**Review!**



**There are IP addresses flagged as _Not Suspicious Traffic._ What are the IP addresses? Enter your answer in numerical order and defanged. (format: IPADDR,IPADDR)**

For this we can filter our logs according to the alert category "Not Suspicious Traffic"



**For the first IP address flagged as Not Suspicious Traffic. According to VirusTotal, there are several domains associated with this one IP address that was flagged as malicious. What were the domains you spotted in the network traffic associated with this IP address? Enter your answer in a defanged format. Enter your answer in alphabetical order, in a defanged format. (format: domain[.]zzz,domain[.]zzz,etc)**




**Now for the second IP marked as Not Suspicious Traffic. What was the domain you spotted in the network traffic associated with this IP address? Enter your answer in a defanged format. (format: domain[.]zzz)**













