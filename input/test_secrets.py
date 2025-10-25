# Test file with obvious hardcoded secrets and tokens
AWS_SECRET = "AKIAEXAMPLESECRETKEY012345"
password = 's3cr3t_pass'

def send():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sometokenpayload"
    print("token length:", len(token))
