#! /usr/bin/env python3
# Utility functions to generate apache style access log entries using non-routable IP addresses

import random
import time

users = ["alice", "bob", "charlie", "dave", "eve", "frank", "greg", "harry", "ian", "jane", "kate", "lisa", "mary", "nancy", "olivia", "paul", "quinn", "rachel", "sarah", "tom", "ursula", "victor", "wendy", "xavier", "yvonne", "zoe"]

def ip():
# Return a random IP address that is not routable on the public internet
    first_octet = random.choice([10, 172, 192])
    if first_octet == 10:
        return ".".join([str(first_octet), str(random.randint(0, 255)), str(random.randint(0, 255)), str(random.randint(0, 255))])
    elif first_octet == 172:
        return ".".join([str(first_octet), str(random.randint(16, 31)), str(random.randint(0, 255)), str(random.randint(0, 255))])
    else:
        return ".".join([str(first_octet), str(168), str(random.randint(0, 255)), str(random.randint(0, 255))])

def timestamp(logtype='access'):
    if logtype == 'access':
        return time.strftime("%d/%b/%Y:%H:%M:%S %z", time.localtime())
    elif logtype == 'auth':
        return time.strftime("%b %d %H:%M:%S", time.localtime())

def http_method():
# Returns a random HTTP method based on the probabilities in the method_probs list
   http_methods = [
    'GET',
    'POST',
    'HEAD',
    'PUT',
    'DELETE'
   ]
   method_probs = [
    0.8,
    0.2,
    0.05,
    0.05,
    0.02
   ]
   return random.choices(http_methods,method_probs,k=1)[0]

def status(good_paths,request):
# Returns a status code 200 if the request path is in the good_paths list
# Otherwise returns a random status code from the following list:
# 400, 401, 403, 404, 500, 503
    if request in good_paths:
        return "200"
    else:
        status_codes = ["400","401","403","404","500","503"]
        return random.choice(status_codes) 

def referrer():
# Returns a random referrer based on the probabilities in the referrer_probs list
    referrers = [
      '-', # 50% chance of no referrer
     'https://www.google.com/',
     'https://www.bing.com/',
     'https://www.yahoo.com/',
     'https://www.ask.com/',
     'https://www.duckduckgo.com/',
     'https://pentest.example.com/'
    ]
    referrer_probs = [
     0.5,
     0.5,
     0.2,
     0.1,
     0.1,
     0.1,
     0.01
    ]

    return random.choices(referrers,referrer_probs,k=1)[0]

def ua(ua_pct):
# Returns a random user agent based on the probabilities in the ua_pct dictionary
# Updated ua_pct can be downloaded here: https://www.useragents.me/api
   return random.choices(list(ua_pct['ua'].values()), list(ua_pct['pct'].values()), k=1)[0]

def generate_access_log_entry(good_paths,bad_paths,ua_pct,remote_ip=""):
# Returns a string with the following format:
# 10.0.0.1 - - [01/Jan/2018:00:00:00 -0500] "GET / HTTP/1.0" 200 1000 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"
    if remote_ip == "":
        remote_ip = ip()
        request = random.choice(good_paths)
    else:
        request = random.choice(bad_paths)
    return remote_ip + " - - [" + timestamp() + "] \"" + http_method() + " " + request + " HTTP/1.0\" " + status(good_paths,request) + " " + str(random.randint(100, 1000)) + " " + referrer() +" \"" + ua(ua_pct) + "\"\n"

def failed_remote_login(hostname,remote_ip):
    logtime = timestamp(logtype='auth')
    pid = str(random.randint(10000, 60000))
    port = str(random.randint(10000, 60000))
    user = random.choice(["hacker", "root", "admin", "administrator", "webmaster", "sysadmin"])
    logline = logtime + " " + hostname + " sshd[" + pid + "]: Invalid user "+ user + " from " + remote_ip + " port " + port + "\n"
    logline += logtime + " " + hostname + " sshd[" + pid + "]: Connection closed by invalid user " + user + " " + remote_ip + " port " + port + " [preauth]\n"
    return logline

def root_cron_session(hostname):
    logtime = timestamp(logtype='auth')
    pid = str(random.randint(10000, 60000))
    logline = logtime + " " + hostname + " CRON[" + pid + "]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)\n"
    logline += logtime + " " + hostname + " CRON[" + pid + "]: pam_unix(cron:session): session closed for user root\n"
    return logline

def user_start_ssh_session(hostname, user_index):
    logtime = timestamp(logtype='auth')
    ssh_pid = str(random.randint(10000, 60000))
    logind_pid = str(random.randint(10000, 60000))
    uid = str(1000 + user_index)
    session_ip = ip()
    rsa_sha = str(random.getrandbits(256))
    port = str(random.randint(10000, 60000))
    session = str(random.randint(1000, 2000))
    logline = logtime + " " + hostname + " sshd[" + ssh_pid + "]: Accepted publickey for " + users[user_index] + " from " + session_ip + " port " + port + " ssh2: RSA SHA256:" + rsa_sha + "\n"
    logline += logtime + " " + hostname + " sshd[" + ssh_pid + "]: pam_unix(sshd:session): session opened for user " + users[user_index] + "(uid=" + uid + ") by (uid=0)\n"
    logline += logtime + " " + hostname + " systemd: pam_unix(systemd-user:session): session opened for user " + users[user_index] + "(uid=" + uid + ") by (uid=0)\n"
    logline += logtime + " " + hostname + " systemd-logind[" + logind_pid + "]: New session " + session + " of user " + users[user_index] + ".\n"
    return logline

def user_end_ssh_session(hostname, user_index):
    logtime = timestamp(logtype='auth')
    ssh_pid = str(random.randint(10000, 60000))
    logind_pid = str(random.randint(10000, 60000))
    session_ip = ip()
    port = str(random.randint(10000, 60000))
    session = str(random.randint(1000, 2000))
    logline = logtime + " " + hostname + " sshd[" + ssh_pid + "]: Received disconnect from " + session_ip + " port " + port + ":11: disconnected by user\n"
    logline += logtime + " " + hostname + " sshd[" + ssh_pid + "]: Disconnected from user " + users[user_index] + " " + session_ip + " port " + port + "\n"
    logline += logtime + " " + hostname + " sshd[" + ssh_pid + "]: pam_unix(sshd:session): session closed for user " + users[user_index] + "\n"
    logline += logtime + " " + hostname + " systemd-logind[" + logind_pid + "]: Session " + session + " logged out. Waiting for processes to exit.\n"
    logline += logtime + " " + hostname + " systemd-logind[" + logind_pid + "]: Removed session " + session + "."
    return logline

