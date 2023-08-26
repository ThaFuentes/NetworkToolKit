import subprocess


def nmap_scan(ip_address):
    command = ["nmap", "-sV", "-O", f"{ip_address}/24"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout if result.returncode == 0 else result.stderr
