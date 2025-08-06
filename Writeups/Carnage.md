
## Introduction




## Scenario


For this scenario we are going to be using a PCAP file, analyzing large files tends to use quite a bit of system resources and the given browser-based AttackBox tends to be limited. Let's instead transfer the PCAP file to our own virtual machine.

*Important Note, pcap files on their own are relatively benign, however the exportable objects that can be contained with them may **not be**. In this example specifically we are going to be exporting malicious scripts that should not be stored on your host operating system; So I strongly reccomend transferring the PCAP file to a virtual machine and not your host OS if you are going to be working along.


**PCAP File Transfer:**

On the browser-based machine **terminal**, move to the directory that contains the pcap file, it should be present at **/Desktop/Analysis**

Next, start an http server with python, this can be very easily done via this one-liner: **python3 -m http.server**

Now move to your VM machine, which should already be connected to the THM VPN and use this command: **wget http://<ATTACK_BOX_IP>:8000/carnage.pcap**  *Note change 'Attack Box IP' to be the ip of the machine hosting the python server, you can find this by using ifconfig on that machine, example:

**<img width="750" height="372" alt="image" src="https://github.com/user-attachments/assets/127fd919-8142-41b1-b976-2b0ad902de3c" />


The file should begin transferring and we can now do analysis more efficently on just our VM machine alone.


## Traffic Analysis

When we open the PCAP file in wireshark we are immediately introduced to 70k packets: <img width="585" height="464" alt="image" src="https://github.com/user-attachments/assets/7a651868-a27a-48eb-a2b6-93e615a83f56" />

Meaning, for this excercise, being intelligent with using wireshark filters is a must.

First question is:

**What was the date and time for the first HTTP connection to the malicious IP?**

**(answer format: yyyy-mm-dd hh:mm:ss)**

This seems like a bit of a strange first question, let's check all of the IP addresses that are present in this file and see if we need more information or not:

To do this in wireshark, Select statistics -> IPV4 Statistics -> and then All Addresses

<img width="696" height="915" alt="image" src="https://github.com/user-attachments/assets/731712cf-6869-4702-9877-5aed00af7df2" />

We can quickly see that there is no easy lead here: <img width="1071" height="560" alt="image" src="https://github.com/user-attachments/assets/8ae0c407-98eb-48bf-90cd-d007f000c18b" />



Lets move to the next question and gather more info on what behavior we should be expecting for the first question.



**What is the name of the zip file that was downloaded?**

We now have a lead on what the malicous IP should be providing, we can use this information to make a wireshark filter or use other methods to idenftify the malicious IP and what zip file is being provided.

Let's first filter for HTTP, HTTP requests are usaully the first sign of compromise:

<img width="1389" height="77" alt="image" src="https://github.com/user-attachments/assets/a8b58461-897b-45a0-a221-a9b872b6ad12" />

The first packet has our answer **documents.zip**, a malicious IP **85.187.128.24** and the victim IP we should be looking for **10.9.23.102**. We should provide **documents.zip** as the answer for our current question and look for all communication to this IP to answer the first question. 

We can easily set a filter for all communication to this **Destination IP** by right clicking the IP, highlighting prepare as filter, and choosing Selected:


<img width="983" height="461" alt="image" src="https://github.com/user-attachments/assets/1593d790-33e7-4868-ac4b-0002af7992e5" />

We can also add another filter for only HTTP requests by adding **and http** to the added **ip.dest** filter:

<img width="958" height="930" alt="image" src="https://github.com/user-attachments/assets/0d7b4272-82fd-4bf5-91ac-83b5490b94d8" />

To view the time of the connection, expand the **Frame** pane on the bottom left.

We now can see the exact time of the only HTTP-GET request to this IP.

our answer should be this (They are looking for UTC time.):

Sep 24, 2021 16:44:38.990412000 -> **Sep 24, 2021 16:44:38**






## Initial Compromise


## C2 Information





