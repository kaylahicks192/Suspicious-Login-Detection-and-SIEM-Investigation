
index=main source="*authentication_logs_example.csv"
| stats count(eval(action="failure")) as Failed_Logins
        count(eval(action="success")) as Successful_Logins
        dc(username) as Targeted_Accounts
        values(username) as Usernames
        by src_ip
| sort - Failed_Logins
