#! /usr/bin/env python3
# Generate apache style access log and secure entries using non-routable IP addresses
# Useful for generating example data for testing log analysis tools like ELK, Splunk, etc.
from data import good_paths, bad_paths, ua_pct, malicious_ips
from utils import generate_access_log_entry, user_end_ssh_session, user_start_ssh_session, failed_remote_login, root_cron_session
import argparse
import random
import time
import socket


def main():
    # Parse the command line arguments
    parser = argparse.ArgumentParser(description='Generate access log entries')
    parser.add_argument(
        '-n','--num_entries',
        required=False,
        default=0, 
        type=int, 
        help='Number of access log entries to generate. Omit for continuous generation. Ctrl-C to exit.'
    )
    parser.add_argument(
        '-i','--interval',
        required=False,
        default=5,
        type=int,
        help='Max interval in seconds between access log entries. Default is 5 seconds.'
    )
    parser.add_argument(
        '-d','--delay',
        required=False,
        default=1,
        type=int,
        help='Delay in seconds before generating the next access log entry. Default is 1 second.'
    )
    parser.add_argument(
        '-a','--access_log',
        required=False,
        default="out/access_log",
        type=str,
        help='File to write access log entries to. Default is out/access_log'
    )
    parser.add_argument(
        '-s','--secure',
        required=False,
        default="out/secure",
        type=str,
        help='File to write secure log entries to. Default is out/secure'
    )    
    parser.add_argument(
        '-H','--hostname',
        required=False,
        default=socket.gethostname(),
        type=str,
        help='Hostname for log entries. Default is system hostname'
    )    
    args = parser.parse_args()
  
    # Print the number of access log entries specified in the argument
    i = 0
    last_time = time.time()

    while i <= args.num_entries:

        secure_log_line = ''
        access_log_line = ''
        if time.time() > last_time + random.choice(range(args.delay,args.interval)):
            if random.randint(0,100) < 10:
                secure_log_line += failed_remote_login(args.hostname,malicious_ips[random.randint(0,19)])
            if random.randint(0,100) < 1:
                secure_log_line += user_start_ssh_session(args.hostname,random.randint(0,25))
            if random.randint(0,100) < 1:
                secure_log_line += user_end_ssh_session(args.hostname,random.randint(0,25))
            if random.randint(0,100) < 50:
                access_log_line = generate_access_log_entry(good_paths,bad_paths,ua_pct, malicious_ips[random.randint(0,19)])
            else:
                access_log_line = generate_access_log_entry(good_paths,bad_paths,ua_pct)

            last_time = time.time()
        if time.time() % 300 == 0: # Every 5 minutes generate a cron job
            secure_log_line += root_cron_session(args.hostname)

        if secure_log_line:
            with open(args.secure,'a') as f:
                f.write(secure_log_line)
        if access_log_line:
            with open(args.access_log,'a') as f:
                f.write(access_log_line)
            
        
        # Only increment the counter if the number of entries has been specified
        # Otherwise loop forever
        if args.num_entries > 0:
            i += 1

        # Record the time of the last loop and sleep for 100ms
        
        time.sleep(.1)

if __name__ == "__main__":
    main()