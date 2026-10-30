# FINDINGS

## First and foremost, I learned how to use the Splunk Enterprise. Although at first, it got tedious, I started to pick up on small coding commands. I strive to learn more regarding SPL in my future projects. Here, I learned the following: 

SIEM - Security Information and Event Management
SIEM - Security Event Management
search logs, identify potential threats, correlate events, and build detection logic

SPL COMMANDS TO UNDERSTAND (Note to self: Make sure you study this coding language daily)

index=main
This is how you get splunk to show you events within the main index. 

index=main action="failure"
Show me the events or "actions" that resulted in a failure. 

EXAMPLE: "Which IP address is responsible for the most failed logins?"
index=main source="*authentication_logs_example.csv"
The source in this case is the file name. 

index=main source="*authentication_logs_example.csv"
action="failure"

It is like you are repeatedly adding filters.

index=main source="*authentication_logs_example.csv"
action="failure"
| stats count by src_ip
Count failed login attempts by SRC_IP (IP ADDress) 
