import nmap
import subprocess
import json
import os

def scan_reseau(ip_range):
    print(f"Scanning network range: {ip_range}")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip_range, arguments='-sn')
    hosts_list = [(host, scanner[host].state()) for host in scanner.all_hosts()]
    print("Scan Results:")
    for host, state in hosts_list:
        print(f"Host: {host} - State: {state}")
    return hosts_list

def ping(target):
    print(f"Pinging target: {target}")
    try:
        # Run the ping command with 4 packets
        result = subprocess.run(['ping', '-c', '4', target], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error: {e}")
        return str(e)

def generate_report(scan_results, ping_result):
    report = {
        "scan_results": [{"host": host, "state": state} for host, state in scan_results],
        "ping_result": ping_result
    }
    # Save the report as a JSON file
    with open("network_report.json", "w") as json_file:
        json.dump(report, json_file, indent=4)
    print("Report saved as network_report.json")

if __name__ == "__main__":
    ip_range = "192.168.1.0/24"  # Change this to your local network range
    scan_results = scan_reseau(ip_range)

    ping_result = ""
    if scan_results:
        target_ip = scan_results[0][0]  # Ping the first host found
        ping_result = ping(target_ip)

    generate_report(scan_results, ping_result)
