import os
import re
from collections import defaultdict
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
#   Uses regular expressions to search for lines in the log file that contain either a [preauth] termination or "Invalid user" messages and extracts the IP addresses from those lines.
#   Counts the occurrences of each IP address for both [preauth] and "Invalid user" scenarios separately.
#   Combines the IPs from both scenarios that have more than 5 occurrences into a set of blacklisted IPs.
#   Writes the blacklisted IPs to blacklisted.txt.
#   adjust the threshold (> 5 in this case) as per your specific requirements.
def extract_ips_from_log(log_file_path):
    # Pattern to extract IP addresses and preauth/invalid user messages
    ip_preauth_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\[preauth\]')
    ip_invalid_user_pattern = re.compile(r'Invalid user \w+ from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    # Count occurrences of IPs for each pattern
    preauth_counts = defaultdict(int)
    invalid_user_counts = defaultdict(int)

    with open(log_file_path, 'r') as file:
        for line in file:
            preauth_match = ip_preauth_pattern.search(line)
            invalid_user_match = ip_invalid_user_pattern.search(line)
            if preauth_match:
                ip = preauth_match.group(1)
                preauth_counts[ip] += 1
            elif invalid_user_match:
                ip = invalid_user_match.group(1)
                invalid_user_counts[ip] += 1

    # Combine the IPs that meet the criteria
    blacklisted_ips = {ip for ip, count in preauth_counts.items() if count > 5} | \
                      {ip for ip, count in invalid_user_counts.items() if count > 5}

    return blacklisted_ips


def add_to_blacklist_and_save(ip_addresses):
    blacklist_file = "blacklisted.txt"
    with open(blacklist_file, "w") as file:
        for ip in ip_addresses:
            file.write(f"{ip}\n")


def main(log_file_path):
    ip_addresses = extract_ips_from_log(log_file_path)
    add_to_blacklist_and_save(ip_addresses)


if __name__ == "__main__":
    log_file_path = input("Enter the path to the log file: ")
    main(log_file_path)
