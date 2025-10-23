import random
import datetime
import sys

ips = ["198.51.100.23", "203.0.113.45", "192.0.2.12"]
users = ["admin", "user", "test", "root", "guest", "oracle"]
time_now = datetime.datetime.now()

with open("samples/generated_auth.log", "w") as f:
    for _ in range(100):
        timestamp = (time_now + datetime.timedelta(seconds=random.randint(1, 2000))).strftime("%b %d %H:%M:%S")
        ip = random.choice(ips)
        user = random.choice(users)
        prompt = f"{timestamp} myhost sshd[1234]: Failed password for invalid user {user} from {ip} port {random.randint(40000, 60000)} ssh2\n"
        f.write(prompt)
        success = True
    if success:
        print("Log generated successfully")
        sys.exit(0)
    else:
        print("Log generation failed")
        sys.exit(1)
