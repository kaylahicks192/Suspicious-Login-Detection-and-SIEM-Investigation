# Suspicious-Login-Detection-and-SIEM-Investigation
Utilizing Splunk Enterprise, SPL, SIEM, VirusTotal to create a Suspicious Login Detection and SIEM Investigation. With the information I find, I will create a Splunk Dashboard, detailing important information times and charts. 

## PROJECT OVERVIEW
This is a simulation of a Security Operations Center (SOC) investigation. We are looking for suspicious employee login activity and potential account compromise. 

In this project, I will 
- Analyze authentication logs
- Investigate a potential brute-force attack
- Use Splunk to develop a dashboard
- Develop incident response recommendations.
- Use prior knowledge of rules and regulations to develop a plan to stop security events/incidents

## TOOLS
- Splunk Enterprise
- SPL
- Windows Event Viewer
- Sysmon
- VirusTotal
- MITRE ATTACK (ADVERSARY TECHNIQUE MAPPING)
- Example database (Created with Claude)

  ## QUICK INFORMATION
  - index=main
| stats count by source    allows users to determine what files they have uploaded.


index=main source="simulated_security_events.csv"
| stats count

This command shows us the quantity of events.


ACCOUNT INVESTIGATION
index=main source="*authentication_logs_example.csv" username="j.smith"
| table _time username src_ip action device
| sort _time

As we can see, we can only find one successful attempt from the IP address: 198.51.100.77
This is very suspicious because there are 22 failed attempts, showing signs of a brute-force attack.

Now, we are going to investigate the financial document. 
index=main source="*simulated_security_events.csv"
| table _time username src_ip file_name action system
| sort _time

transfer_review_2400000.xlsx has two copies, and they're both DENIED. DIGITAL EVIDENCE COORELATION, putting pieces together. 

index=main
(source="*authentication_logs_example.csv"
OR source="*simulated_security_events.csv")
src_ip="198.51.100.77"
| eval event_type=if(
    like(source,"%authentication_logs_example.csv"),
    "Authentication",
    "File Access"
  )
| eval details=if(
    event_type="Authentication",
    "Login: ".action,
    "File: ".file_name." / ".action
  )
| table _time username src_ip event_type details
| sort _time

This makes a timeline. 

We see the times of all events, and how so many events were declined. This points to a security incident, an account is showing signs of being compromised. 

DETECTION RULE
index=main source="*authentication_logs_example.csv"
action="failure"
| bin _time span=5m
| stats count as failed_attempts by src_ip _time
| where failed_attempts >= 5
| sort - failed_attempts

"Show me any IP address with at least five failed login attempts within a five-minute time bucket."

index=main source="*authentication_logs_example.csv"
| stats count(eval(action="failure")) as Failed
        count(eval(action="success")) as Successful
        by src_ip
| sort - Failed

198.51.100.77, which is associated with repeated failed logins and a later success in our simulated scenario.

You should see a table with the IP addresses and how many failed and successful logins each has.

stats groups evidence and eval allows you to count events meeting specific conditions.

index=main source="*authentication_logs_example.csv"
username="j.smith"
| table _time username src_ip action device
| sort _time

FILTERS RESULTS TO ONE PERSON
________________________________________________________________

index=main source="*simulated_security_events.csv"
| table _time username src_ip file_name action system
| sort _time

EVENT AFTER LOG IN 

________________________________________________________________
These events are coming from j.smith, and we see that 2 events are denied. transfer_review_2400000.xlsx

_________________________________________________________________
index=main
(source="*authentication_logs_example.csv" OR source="*simulated_security_events.csv")
src_ip="198.51.100.77"
| eval event_type=if(
    like(source,"%authentication_logs_example.csv"),
    "Authentication",
    "File Access"
  )
| eval details=if(
    event_type="Authentication",
    "Login: ".action,
    "File: ".file_name." / ".action
  )
| table _time username src_ip event_type details
| sort _time
timeline combining login attempts and file-access records from the suspicious IP
EVENT COORELATION  - skill 

____________________________________________________________________________________

Making Dashboard 
timechart creates a chart using timestamps.
span=5m groups activity into five-minute intervals.
count by action separates successful and failed logins.


_____________________________________________________________________________________
SUSPICIOUS IP CHART

index=main source="*authentication_logs_example.csv"
action="failure"
| stats count as Failed_Logins by src_ip
| sort - Failed_Logins

_____________________________________________________________________________________
index=main source="*authentication_logs_example.csv"
action="failure"
| stats count as Failed_Logins by username
| sort - Failed_Logins

targeted employee chart
______________________________________________________________________________________
index=main
(source="*authentication_logs_example.csv" OR source="*simulated_security_events.csv")
src_ip="198.51.100.77"
| eval Event_Type=if(like(source,"%authentication_logs_example.csv"),"Authentication","File Access")
| eval Details=if(Event_Type="Authentication","Login: ".action,"File: ".file_name." / ".action)
| table _time username src_ip Event_Type Details
| sort _time

INCIDENT TIMELINE

_____________________________________________________________________________________


install Sysmon from Microsoft and investigate a harmless Notepad process using Event ID 1.

Windows events and results from sysmon are from Home PC. They are considered separate activities to prove my proficiency in Sysmon and Windows Events.
___________________________________________________________________________________
LAST: MITRE ATT&CK MAPPING

What is MITRE ATT&CK? It is a knowledge base documenting techniques that real attackers use against computer systems.

connect suspicious security events to known attacker techniques


