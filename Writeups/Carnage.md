
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


**What was the domain hosting the malicious zip file?**

To check this, we can stay on our current highlighted packet, we merely just need to open the HTTP section of the packet which is found at the bottom:

<img width="957" height="769" alt="image" src="https://github.com/user-attachments/assets/f52bbfcf-84af-46bb-b3ea-11d6ba360a62" />

And take the domain found in the **Full Request URI**: hxxp[:]//attirenepal[.]com/incidunt-consequatur/documents[.]zip

The answer is attirenepal[.]com (Defanged).



**Without downloading the file, what is the name of the file in the zip file?**

Here we are going to be interacting with the sample itself, we are going to export the downloaded malicous zip artifact and then unzip it to see what it contains, it goes without saying this should be done in a safe environment.

To do this in Wireshark, go to **File** -> **Export Objects** -> and Select **HTTP**

<img width="586" height="576" alt="image" src="https://github.com/user-attachments/assets/26bcc09c-4adc-4274-bdc3-d59e0e37f179" />

<img width="765" height="545" alt="image" src="https://github.com/user-attachments/assets/52a93934-8eba-4416-aa71-64d0034ec7ac" />

Here we can see that the first object is the Malicious Zip file, but if this wasnt the case we could search for the .zip file extension and filter the results, select the file and choose save.

Now let's see what this .zip file contains:

<img width="600" height="498" alt="image" src="https://github.com/user-attachments/assets/0ab8cf67-5bcd-424f-8c81-fb1a668d488a" />

We can see that it is an excel spreadsheet, meaning, this spreadsheet likely had a malicious macro that initiated the infection once run. This is a very common tactic bundled with Phishing attempts and if we desired we could also analyze the spread sheet for malicious macros via some static analysis tools.

For this question however, our answer is **chart-1530076591.xls**

**What is the name of the webserver of the malicious IP from which the zip file was downloaded?**

Now we are getting a bit deeper into forensics and analyzing the tracks of the threat actor, we now should look at the full stream of communication with this IP and see what we can get in the request headers:


To follow the full conversation that occurred with a specific IP/packet right click on that packet, click follow, and choose HTTP or TCP stream respectively. We are doing HTTP in this case: 

<img width="777" height="446" alt="image" src="https://github.com/user-attachments/assets/ea67ac99-5433-4acb-96f7-c2ac623465d0" />

<img width="1269" height="877" alt="image" src="https://github.com/user-attachments/assets/15ca1c40-541d-435f-8bd2-1bf39f33abfa" />

Now we can see the entire conversation in a nice and readable format, we also can see the webserver that was used for the transfer in the headers:

<img width="683" height="327" alt="image" src="https://github.com/user-attachments/assets/2333e488-fee8-49f6-9aca-2d8c2da26297" />

Our answer for this question is **LiteSpeed.**

**What is the version of the webserver from the previous question?**

We can quickly grab the php version too while we are still on this steam's info pane:

<img width="646" height="336" alt="image" src="https://github.com/user-attachments/assets/dce83064-425e-4829-a13d-adb9e3e22a08" />

Our answer to that question should be: **PHP/7.2.34**


**Malicious files were downloaded to the victim host from multiple domains. What were the three domains involved with this activity?**

This question took a lot of trial and error without checking the hint, I personally believe they should have included the fact that these requests are SSL (HTTPS) in the question itself rather than the hint. Let's check the hint quickly to save time:

<img width="366" height="265" alt="image" src="https://github.com/user-attachments/assets/1eba4c5c-ecb5-43a4-a7af-d3c580af91fc" />

Ok, so now we know we are specifically only supposed to be looking for HTTPS traffic. We can set that filter on wireshark:

*Note that the filter for this is not _HTTPS_ on wireshark but _TLS_ for some reason.

<img width="1567" height="478" alt="image" src="https://github.com/user-attachments/assets/333033e2-7c1f-4bc9-9801-663f6e1f8504" />

There is a total of over 10k packets, even when filtering for TLS, this is due to numerous reasons such as Microsoft telemetry being sent via the HTTPS protocol. 


## Initial Compromise


## C2 Information





