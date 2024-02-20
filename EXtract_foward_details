import os
import re
import smtplib
from collections import defaultdict
import geopandas as gpd
import matplotlib.pyplot as plt
from collections import Counter
import requests
import platform
from requests import get
import pandas as pd
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from dotenv import load_dotenv
import socket
import psutil

# Load environment variables
load_dotenv()
log_file_path = "auth.log" # path to your auth.log file
# Get the current working directory
current_dir = os.getcwd()
system_info = "systeminfo.txt"
system_file_path = os.path.join(current_dir, system_info)


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


def fetch_geolocation(ip):
    """Fetch geolocation data for a given IP."""
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,lat,lon")
        data = response.json()
        if data['status'] == 'success':
            return {
                'IP': ip,
                'Country': data.get('country', 'Not found'),
                'Region': data.get('regionName', 'Not found'),
                'City': data.get('city', 'Not found'),
                'ISP': data.get('isp', 'Not found'),
                'Latitude': data.get('lat', 'Not found'),
                'Longitude': data.get('lon', 'Not found')
            }
        else:
            return {
                'IP': ip,
                'Error': data.get('message', 'Failed to fetch data')
            }
    except Exception as e:
        # Log exceptions encountered during the request
        return {
            'IP': ip,
            'Error': str(e)
        }


def save_detailed_data(geolocation_data):
    """Save detailed data to a file, and log errors if they occur."""
    detailed_file = "blacklisted_details.txt"
    error_log_file = "error_log.txt"

    with open(detailed_file, "w") as file, open(error_log_file, "a") as error_file:
        for data in geolocation_data:
            # Check if 'Error' key exists in data dictionary
            if 'Error' in data and data['Error']:
                # Log the error and skip this entry
                error_message = f"Error fetching data for IP {data['IP']}: {data['Error']}\n"
                error_file.write(error_message)
                continue  # Skip saving this entry

            # Assuming success, write the geolocation details
            file.write(f"IP: {data['IP']}\n")
            file.write(f"Country: {data.get('Country', 'Not found')}\n")
            file.write(f"Region: {data.get('Region', 'Not found')}\n")
            file.write(f"City: {data.get('City', 'Not found')}\n")
            file.write(f"ISP: {data.get('ISP', 'Not found')}\n")
            file.write(f"Latitude: {data.get('Latitude', 'Not found')}\n")
            file.write(f"Longitude: {data.get('Longitude', 'Not found')}\n")
            file.write("\n")  # Add a newline for readability between IP blocks


# Assuming geolocation_data is a list of dictionaries returned by fetch_geolocation
def aggregate_ip_data_by_country(geolocation_data):
    # Filter out any entries with errors
    valid_data = [data for data in geolocation_data if 'Error' not in data]

    # Create a DataFrame
    df = pd.DataFrame(valid_data)

    # Aggregate data by country
    country_counts = df.groupby('Country').size().reset_index(name='IP_Count')

    return country_counts

#the retry function is not used in this instance
def retry_error_ips():
    error_log_file = "error_log.txt"
    retry_ips = []

    # Regex pattern to extract IP addresses from error log entries
    ip_pattern = re.compile(r'Error fetching data for IP (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):')

    # Read error_log.txt and extract IPs
    with open(error_log_file, "r") as file:
        for line in file:
            match = ip_pattern.search(line)
            if match:
                retry_ips.append(match.group(1))

    if not retry_ips:
        print("No IPs to retry.")
        return

    # Attempt to fetch geolocation data for the IPs that previously resulted in errors
    geolocation_data = [fetch_geolocation(ip) for ip in retry_ips]

    # Save the new results, updating the detailed data and error log as necessary
    save_detailed_data(geolocation_data)

    # Optionally, clear the error log if all retries were successful, or rewrite it with remaining errors
    with open(error_log_file, "w") as error_file:
        remaining_errors = [data for data in geolocation_data if 'Error' in data and data['Error']]
        for data in remaining_errors:
            error_message = f"Error fetching data for IP {data['IP']}: {data['Error']}\n"
            error_file.write(error_message)

    print(f"Retried {len(retry_ips)} IPs. Check 'blacklisted_details.txt' and 'error_log.txt' for updates.")


def generate_country_chart(geolocation_data):
    countries = [data.get('Country', 'Not found') for data in geolocation_data if data.get('Country')]
    country_counts = Counter(countries)

    plt.figure(figsize=(10, 8))
    plt.bar(country_counts.keys(), country_counts.values(), color='skyblue')
    plt.xlabel('Country')
    plt.ylabel('Number of IPs')
    plt.title('IP Distribution by Country')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('ip_distribution.png')


def computer_information():
    with open(system_file_path, 'a') as f:
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)

        f.write("Processor Info: " + platform.processor() + "\n")
        f.write("System: " + platform.system() + " " + platform.version() + "\n")
        f.write("Machine: " + platform.machine() + "\n")
        f.write("Hostname: " + hostname + "\n")
        f.write("Private IP Address: " + IPAddr + "\n")

        f.write("\nActive Processes:\n")
        processes = psutil.process_iter()
        for process in processes:
            try:
                process_name = process.name()
                process_id = process.pid
                f.write("Name: {}  ID: {}\n".format(process_name, process_id))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Handle exceptions if the process no longer exists or access is denied
                pass

def generate_ip_map(df):
    # Load a map of the world
    world = gpd.read_file(gpd.datasets.get_path('naturalearth_lowres'))

    # Merge the world map with your IP data
    world = world.merge(df, how="left", left_on="name", right_on="Country")

    # Plot
    fig, ax = plt.subplots(1, 1, figsize=(15, 10))
    world.boundary.plot(ax=ax)
    world.plot(column='IP_Count', ax=ax, legend=True,
               legend_kwds={'label': "Number of Blacklisted IPs by Country"},
               cmap='OrRd', missing_kwds={'color': 'lightgrey'})

    plt.savefig('ip_map.png')

def send_email(subject, attachments=[]):
    email_user = os.getenv("EMAIL_USER")
    email_password = os.getenv("EMAIL_PASSWORD")
    recipient = email_user

    message = MIMEMultipart()
    message["From"] = email_user
    message["To"] = recipient
    message["Subject"] = subject

    # Instructions for manually retrieving IP details, including public and private IP
    public_ip = get('https://api.ipify.org').text
    instructions = f"""

Public IP address: {public_ip}

To manually retrieve geolocation details for IPs that encountered errors during the automated process, you can use the following command:

For Unix/Linux:
curl http://ip-api.com/json/{{IP_ADDRESS}}

For Windows (PowerShell):
Invoke-RestMethod http://ip-api.com/json/{{IP_ADDRESS}}

Please replace "{{IP_ADDRESS}}" with the actual IP address you wish to query.

Attached are the details of blacklisted IPs and any errors encountered during the automated retrieval process.
"""

    message.attach(MIMEText(instructions, "plain"))

    # Attach files
    for attachment in attachments:
        with open(attachment, "rb") as file:
            part = MIMEApplication(file.read(), Name=os.path.basename(attachment))
        part['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment)}"'
        message.attach(part)

    text = message.as_string()

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(email_user, email_password)
        server.sendmail(email_user, recipient, text)


def main():
    # Implement the main logic including:
    # 1. Reading IPs from blacklisted.txt and fetching geolocation data
    # 2. Retrying for IPs in error_log.txt
    # 3. Generating country chart
    # 4. Composing and sending the email with attachments and instructions
    ip_addresses = extract_ips_from_log(log_file_path)
    add_to_blacklist_and_save(ip_addresses)
    with open("blacklisted.txt", "r") as file:
        ip_addresses = [line.strip() for line in file.readlines()]

    geolocation_data = [fetch_geolocation(ip) for ip in ip_addresses]
    save_detailed_data(geolocation_data)
    # Aggregate IP data by country
    country_counts_df = aggregate_ip_data_by_country(geolocation_data)
    # Generate the IP map
    generate_ip_map(country_counts_df)
    #    retry_error_ips()
    generate_country_chart(geolocation_data)
    computer_information()
    subject = "IP Geolocation Report and Manual Retrieval Instructions"
    attachments = ["blacklisted.txt", "blacklisted_details.txt", "error_log.txt", "ip_distribution.png",
                   "systeminfo.txt", "ip_map.png"]  # Assuming these files exist
    send_email(subject, attachments)


if __name__ == "__main__":
    main()
