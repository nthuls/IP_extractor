import requests

def get_ip_info(ip_address):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error obtaining IP information: {e}")
        return None

def print_ip_info(info):
    if info and info['status'] == 'success':
        for key, value in info.items():
            print(f"{key.title()}: {value}")
    else:
        print("Failed to retrieve information or IP address not found.")

def main():
    ip = input("Enter the IP address: ").strip()
    
    if ip:
        info = get_ip_info(ip)
        print_ip_info(info)
    else:
        print("No valid IP address provided.")

if __name__ == "__main__":
    main()
