import subprocess
import json


def get_ssids():
    command = "netsh wlan show networks mode=bssid"
    result = subprocess.run(command, stdout=subprocess.PIPE, text=True, shell=True)
    lines = result.stdout.split('\n')
    networks = []
    network = {}
    for line in lines:
        line = line.strip()
        if "SSID" in line and "BSSID" not in line:
            if network:  # Save the previous network if there is one
                networks.append(network)
            network = {"SSID": line.split(":")[1].strip()}
        elif "BSSID" in line or "Signal" in line or "Channel" in line:
            key, value = line.split(":", 1)  # Split at the first colon only
            network[key.strip()] = value.strip()

    if network:  # Save the last network
        networks.append(network)

    return networks


ssids = get_ssids()

# Save to a JSON file
with open('ssids.json', 'w') as json_file:
    json.dump(ssids, json_file)

print("Wi-Fi networks have been saved to ssids.json")
