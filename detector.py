import scapy.all as scapy
import os
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)  # autoreset=True automatically resets colors after each print

def get_mac(ip):
    # Function to get the MAC address of a given IP using ARP requests
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def sniff(interface, output_file, detected_mitm_set):
    try:
        # Sniff function to capture and process packets on the specified network interface
        scapy.sniff(iface=interface, store=False, prn=lambda x: process_sniffed_packet(x, output_file, detected_mitm_set))
    except Exception as e:
        print(f"Error: {e}")

def process_sniffed_packet(packet, output_file, detected_mitm_set):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            # Process ARP packets to identify potential MITM attacks
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                # If MAC addresses do not match, potential MITM attack detected
                victim_ip = packet[scapy.ARP].psrc
                victim_mac = real_mac
                attacker_mac = response_mac

                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_message = f"[!] Possible MITM Attack Detected at {current_time}!\n" \
                                f"    [+] Victim IP: {victim_ip}\n" \
                                f"    [+] Victim MAC (before attack): {victim_mac}\n" \
                                f"    [+] Attacker MAC: {attacker_mac}\n"

                if (victim_ip, victim_mac) not in detected_mitm_set:
                    # If this incident is new, log and print the alert
                    with open(output_file, 'a') as notepad:
                        notepad.write(alert_message + "\n\n")
                        print(Fore.GREEN + alert_message + Style.RESET_ALL)
                        detected_mitm_set.add((victim_ip, victim_mac))
        except IndexError:
            pass

def clear_notepad(output_file):
    try:
        # Function to clear the notepad file
        with open(output_file, 'w') as notepad:
            notepad.write("[+] Notepad cleared!\n")
    except Exception as e:
        print(f"Error: {e}")

def print_ascii_logo():
    # Function to print the ASCII logo for the MITM Detection Tool
    ascii_logo = """
    
$$$$$$$$\ $$\   $$\ $$$$$$$\    $$\    $$$$$$\  
$$  _____|$$ |  $$ |$$  __$$\ $$$$ |  $$  __$$\ 
$$ |      $$ |  $$ |$$ |  $$ |\_$$ |  $$ /  \__|
$$$$$\    $$$$$$$$ |$$$$$$$  |  $$ |  \$$$$$$\  
$$  __|   \_____$$ |$$  __$$<   $$ |   \____$$\ 
$$ |            $$ |$$ |  $$ |  $$ |  $$\   $$ |
$$ |            $$ |$$ |  $$ |$$$$$$\ \$$$$$$  |
\__|            \__|\__|  \__|\______| \______/ 
                                                
                                                
                                                
"""
    print(Fore.CYAN + ascii_logo + Style.RESET_ALL)

if __name__ == "__main__":
    os.system("clear" if os.name == "posix" else "cls")
    print_ascii_logo()

    output_file = "logs.txt"
    detected_mitm_set = set()
    print("[+] MITM Detection Tool - Press Ctrl+C to exit")

    try:
        network_interface = input(f"{Fore.YELLOW}Enter your network interface (e.g., eth0): {Style.RESET_ALL}")

        while True:
            user_input = input(f"\n{Fore.YELLOW}Enter '1' to run the detector or '2' to clear the notepad: {Style.RESET_ALL}")
            if user_input == '1':
                sniff(network_interface, output_file, detected_mitm_set)
            elif user_input == '2':
                clear_notepad(output_file)
                print(f"{Fore.RED}[+] Notepad cleared!{Style.RESET_ALL}")
                detected_mitm_set.clear()
            else:
                print("Invalid input. Please enter '1' to run the detector or '2' to clear the notepad.")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[+] Exiting the MITM detection tool.{Style.RESET_ALL}")
