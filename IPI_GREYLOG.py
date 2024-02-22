import os
import re
import smtplib
import geopandas as gpd
import matplotlib.pyplot as plt
import requests
from collections import defaultdict, Counter
import platform
from requests import get
import pandas as pd
from collections import Counter
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from dotenv import load_dotenv
import socket
import psutil

load_dotenv()
log_file_path = "../auth.log"
current_dir = os.getcwd()
system_info = "systeminfo.txt"
system_file_path = os.path.join(current_dir, system_info)
api_key = os.getenv('GREYNOISE_API_KEY')
def extract_ips_from_log(log_file_path):
    ip_preauth_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\[preauth\]')
    ip_invalid_user_pattern = re.compile(r'Invalid user \w+ from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
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
    blacklisted_ips = {ip for ip, count in preauth_counts.items() if count >= 5} | {ip for ip, count in invalid_user_counts.items() if count >= 5}
    return blacklisted_ips

def add_to_blacklist_and_save(ip_addresses):
    blacklist_file = "blacklisted.txt"
    with open(blacklist_file, "w") as file:
        for ip in ip_addresses:
            file.write(f"{ip}\n")

def fetch_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,lat,lon")
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
            return {'IP': ip, 'Error': data.get('message', 'Failed to fetch data')}
    except Exception as e:
        return {'IP': ip, 'Error': str(e)}

def save_detailed_data(geolocation_data):
    detailed_file = "blacklisted_details.txt"
    error_log_file = "error_log.txt"
    with open(detailed_file, "w") as file, open(error_log_file, "a") as error_file:
        for data in geolocation_data:
            if 'Error' in data and data['Error']:
                error_message = f"Error fetching data for IP {data['IP']}: {data['Error']}\n"
                error_file.write(error_message)
                continue
            file.write(f"IP: {data['IP']}\n")
            for key, value in data.items():
                if key != 'IP':
                    file.write(f"{key}: {value}\n")
            file.write("\n")

def extract_ips_from_error_log(file_path='error_log.txt'):
    ip_pattern = re.compile(r'IP (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    ips = set()
    with open(file_path, 'r') as file:
        for line in file:
            match = ip_pattern.search(line)
            if match:
                ips.add(match.group(1))
    return ips


def query_greynoise(ip_address, api_key):
    url = f"https://api.greynoise.io/v3/community/{ip_address}"
    headers = {'key': api_key}
    try:
        response = requests.get(url, headers=headers)
        return response.json()  # Return the JSON response directly
    except Exception as e:
        return {'IP': ip_address, 'Error': str(e)}

def write_greynoise_data_to_file(ips, api_key, output_file='greynoise.txt'):
    with open(output_file, 'w') as file:
        for ip in ips:
            data = query_greynoise(ip, api_key)
            file.write(f"IP: {ip}\n")
            for key, value in data.items():
                file.write(f"{key}: {value}\n")
            file.write("\n")  # Add a newline for readability between IP entries

def aggregate_ip_data_by_country(geolocation_data):
    valid_data = [data for data in geolocation_data if 'Error' not in data]
    df = pd.DataFrame(valid_data)
    country_counts = df.groupby('Country').size().reset_index(name='IP_Count')
    return country_counts

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

def generate_ip_map(df):
    shapefile_path = os.path.join(current_dir, '../', 'data', 'naturalearth_lowres', 'ne_110m_admin_0_countries.shp')
    world = gpd.read_file(shapefile_path)
    #print(world.columns)  # Add this line to inspect the column names
    world = world.merge(df, how="left", left_on="ADMIN", right_on="Country")
    fig, ax = plt.subplots(1, 1, figsize=(15, 10))
    world.boundary.plot(ax=ax)
    world.plot(column='IP_Count', ax=ax, legend=True,
               legend_kwds={'label': "Number of Blacklisted IPs by Country"},
               cmap='OrRd', missing_kwds={'color': 'lightgrey'})
    plt.savefig('ip_map.png')

def computer_information():
    with open(system_file_path, 'a') as f:
        hostname = socket.gethostname()
        internal_IPAddr = socket.gethostbyname(hostname)  # Fetches the internal IP address

        f.write("Processor Info: " + platform.processor() + "\n")
        f.write("System: " + platform.system() + " " + platform.version() + "\n")
        f.write("Machine: " + platform.machine() + "\n")
        f.write("Hostname: " + hostname + "\n")
        f.write("Private IP Address: " + internal_IPAddr + "\n")
        # Fetch and write network interface information
        f.write("\nNetwork Interfaces and IP Addresses:\n")
        addrs = psutil.net_if_addrs()
        for interface_name, interface_addresses in addrs.items():
            for address in interface_addresses:
                if address.family == socket.AF_INET:  # Adjusted for direct comparison
                    # Print to console
                    print(f"Interface: {interface_name}")
                    print(f"  IP Address: {address.address}")
                    print(f"  Netmask: {address.netmask}")
                    print(f"  Broadcast IP: {address.broadcast}")

                    # Write to file
                    f.write(f"Interface: {interface_name}\n")
                    f.write(f"  IP Address: {address.address}\n")
                    f.write(f"  Netmask: {address.netmask}\n")
                    f.write(f"  Broadcast IP: {address.broadcast}\n\n")
                    f.write("\nEnd of Network Interfaces\n")

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

def send_email(subject, attachments=[]):
    email_user = os.getenv("EMAIL_USER")
    email_password = os.getenv("EMAIL_PASSWORD")
    recipient = email_user
    message = MIMEMultipart()
    message["From"] = email_user
    message["To"] = recipient
    message["Subject"] = subject
    public_ip = get('https://api.ipify.org').text
    instructions = f"Public IP address: {public_ip}\n\nTo manually retrieve geolocation details for IPs that encountered errors during the automated process, use the following command:\n\nFor Unix/Linux:\ncurl http://ip-api.com/json/{{IP_ADDRESS}}\n\nFor Windows (PowerShell):\nInvoke-RestMethod http://ip-api.com/json/{{IP_ADDRESS}}\n\nPlease replace \"{{IP_ADDRESS}}\" with the actual IP address you wish to query.\n\nAttached are the details of blacklisted IPs and any errors encountered during the automated retrieval process."
    message.attach(MIMEText(instructions, "plain"))
    for attachment in attachments:
        with open(attachment, "rb") as file:
            part = MIMEApplication(file.read(), Name=os.path.basename(attachment))
        part['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment)}"'
        message.attach(part)
    text = message.as_string()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(email_user, email_password)
        server.sendmail(email_user, recipient, text)

def delete_attachments(attachments):
    for attachment in attachments:
        if attachment != "blacklisted.txt":  # Skip blacklisted.txt
            try:
                os.remove(attachment)
                print(f"Deleted {attachment}")
            except OSError as e:
                print(f"Error deleting {attachment}: {e}")
def main():
    ip_addresses = extract_ips_from_log(log_file_path)
    add_to_blacklist_and_save(ip_addresses)
    geolocation_data = [fetch_geolocation(ip) for ip in ip_addresses]
    save_detailed_data(geolocation_data)
    error_ips = extract_ips_from_error_log()
    if error_ips:
        write_greynoise_data_to_file(error_ips, api_key)
    else:
        print("No IPs found in error_log.txt or the file doesn't exist.")

    country_counts_df = aggregate_ip_data_by_country(geolocation_data)
    generate_ip_map(country_counts_df)
    generate_country_chart(geolocation_data)
    computer_information()
    subject = "IP Geolocation Report and Manual Retrieval Instructions"
    attachments = ["blacklisted.txt", "blacklisted_details.txt", "error_log.txt", "ip_distribution.png", "ip_map.png", "systeminfo.txt", "greynoise.txt"]
    send_email(subject, attachments)

    # Delete attachments after sending the email
    delete_attachments(attachments)

if __name__ == "__main__":
    main()
