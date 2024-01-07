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
        ![Screenshot_2](https://github.com/unfrs/MITM-detection/assets/107608491/1d56e2ff-32d4-40de-8fb2-22ac1b22f264)
        ![Screenshot_1](https://github.com/unfrs/MITM-detection/assets/107608491/619b9a2a-dc2f-4f83-a064-0445bb0e684b)


    Exiting:
        Press Ctrl+C to exit the MITM Detection Tool.

By following these simple steps, users can enhance their network security and stay vigilant against potential MITM threats.
