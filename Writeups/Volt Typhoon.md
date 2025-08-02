

**Hello!**

This is a write-up of the Volt Typhoon challenge on Tryhackme. **Volt Typhoon** is an infamous APT assumed to be of Chinese Origin that focus on espionage, data theft, and credential exfiltration.

It has different names from multiple different threat analysis research groups and is very stealthy in their actions post foothold, using nearly entirely only LOLBins (Living off The Land binaries), such as  wmic, ntdsutil, and netsh.

Mitre has a detailed paper highlighting their TTPs, links, and other information regarding this group here: https://attack.mitre.org/groups/G1017/ . CISA also similarily has an analysis here: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a . They have successfully

breached and exploited multiple Western government instituions.


Today we are going to be doing the Splunk focused Tryhackme Challenge that uses the TTPs and the IOCs consistent with this APT based on logs of actual compromises:


Firstly we access the Splunk instance


