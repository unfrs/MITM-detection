Brief Description:

The MITM Detection Tool is a lightweight Python script designed to identify and alert users to potential Man-in-the-Middle (MITM) attacks within a local network. Leveraging the Scapy library, the tool monitors network traffic for signs of ARP spoofing, a common technique used in MITM attacks. By maintaining a notepad of previously detected incidents and displaying alerts with color-coded output, the tool enhances user awareness and aids in timely response to security threats.

How It Works:

The tool employs ARP (Address Resolution Protocol) packet analysis to detect inconsistencies between actual and reported MAC addresses, a telltale sign of ARP spoofing. When a potential MITM attack is identified, the script logs essential details such as victim IP addresses, MAC addresses, and timestamps. The colored output provides a quick visual indication of the severity of the alert, while the notepad ensures that only new alerts are displayed, minimizing redundancy.

Why We Built It:

The MITM Detection Tool was created to address the growing threat of MITM attacks, which can compromise the confidentiality and integrity of network communications. By offering a simple, yet effective, detection mechanism, the tool empowers users to proactively identify and respond to potential security breaches. It serves as an essential component of network security strategies, helping users maintain the integrity of their local networks.

How to Use:

    Installation:
        git clone https://github.com/unfrs/MITM-detection.git
        pip install -r requirements.txt.

    Run the Tool:
        Execute the script: sudo python detector.py
        Enter your network interface when prompted (e.g., eth0).

    Operation:
        Enter '1' to run the detector or '2' to clear the notepad.

    Exiting:
        Press Ctrl+C to exit the MITM Detection Tool.

![Screenshot_2](https://github.com/unfrs/MITM-detection/assets/107608491/3e0cfc19-410d-47b5-832a-e1523f65462c)
![Screenshot_1](https://github.com/unfrs/MITM-detection/assets/107608491/7e624bed-c9ad-4610-b2be-2f89876cbf2a)

By following these simple steps, users can enhance their network security and stay vigilant against potential MITM threats.
