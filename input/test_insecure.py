# Test file exercising insecure function usage and SQL heuristics
import subprocess
import pickle
import hashlib
import re

password = "hunter2"
API_KEY = "ABCD1234SECRETKEYSHOULDNOTBEHERE"

# insecure eval
user_input = "2 + 2"
res = eval(user_input)

# subprocess with shell=True
subprocess.run("ls -la", shell=True)

# insecure pickle loads (simulated)
# normally: data = pickle.loads(s)
# here we call pickle.loads on a string to show detection pattern
try:
    obj = pickle.loads(b"not-a-pickle")
except Exception:
    pass

# deprecated hashes
h = hashlib.md5(b"data").hexdigest()

# regex overly broad
pat = re.compile('.*')

# SQL-like concatenation
query = "SELECT * FROM users WHERE name = '" + user_input + "'"
# emulate execute without params
cursor = None
try:
    cursor.execute(query)
except Exception:
    pass
