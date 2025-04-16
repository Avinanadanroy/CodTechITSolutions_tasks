# Basic Pentesting Toolkit in KALI LINUX

*COMPANY* : CODTECH IT SOLUTIONS<br>
*NAME* : AVINANADAN ROY<br>
*INTERN id* : CT04WT128<br>
*DOMAIN* : Cyber Security & Ethical Hacking<br>
*DURATION* : 4 Weeks<br>
*MENTOR* : NEELA SANTOSH<br>

---

Welcome to the Basic Pentesting Toolkit! This toolkit provides a set of modules for performing various penetration testing tasks, including port scanning, network sniffing, brute forcing, and vulnerability scanning.

---

## Prerequisites

- `Kali linux`
- `DVWA (Damn Vulnerable Web Application)`

Before running the toolkit, ensure you have the following Python packages installed:

- `requests`
- `beautifulsoup4`
- `scapy`
- `pyshark`
- `paramiko`
- `python-nmap`

You can install these packages using pip:

bash
`pip install requests beautifulsoup4 scapy pyshark paramiko python-nmap`

---

### Download and configure DVWA for safe Pentesting

1. Download the script:
    `wget https://raw.githubusercontent.com/IamCarron/DVWA-Script/main/Install-DVWA.sh`

2. Make the script executable: 
    `chmod +x Install-DVWA.sh`

3. Run the script as root:
    `sudo ./Install-DVWA.sh`

---

## Modules

The toolkit consists of the following modules:

1. **Port Scanner** (`port_scanner.py`): Scans a specified range of ports on a target host to identify open ports.
2. **Network Sniffer** (`network_sniffer.py`): Captures and analyzes network packets in real-time.
3. **Brute Forcer** (`brute_forcer.py`): Attempts to gain unauthorized access to a service by trying multiple password combinations.
4. **Vulnerability Scanner** (`vuln_scanner.py`): Scans a target for known vulnerabilities.

---

## Run main python script

bash
`python main.py`

`[*] Welcome to the Basic Pentesting Toolkit
[*] Available modules:
    1. Port Scanner (port_scanner)
    2. Network Sniffer (network_sniffer)
    3. Brute Forcer (brute_forcer)
    4. Vulnerability Scanner (vuln_scanner)
    5. Exit`

---

### OUTPUTS

- Port scanner output
![Image](https://github.com/user-attachments/assets/77eac633-0e9f-4daf-ac70-e3fdecc8eb3c)

- Network sniffer output
![Image](https://github.com/user-attachments/assets/69fcecae-fcdc-4dab-aab6-81c267a50ad7)

- Brute forcer output
![Image](https://github.com/user-attachments/assets/f18e9f57-93f3-4a18-b5c0-714485f90d7d)

- Vuln scanner SQL injection output
![Image](https://github.com/user-attachments/assets/ab292ec1-c82f-4a0c-ab20-e27aafd5a26c)

- Vuln scanner XSS output
![Image](https://github.com/user-attachments/assets/1ef4d29f-c23c-4d4e-8c5c-870269b09fd7)
