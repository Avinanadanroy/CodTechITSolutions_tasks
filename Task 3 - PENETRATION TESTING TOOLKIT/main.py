import subprocess
import sys
import os

MODULES_DIR = "modules"

def run_module(module_name):
    """Runs a specified module as a subprocess."""
    module_path = os.path.join(MODULES_DIR, f"{module_name}.py")
    try:
        print(f"\n[*] Running module: {module_name}.py from {MODULES_DIR}/")
        subprocess.run([sys.executable, module_path], check=True)
        print(f"[*] Module {module_name}.py finished.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running module {module_name}.py: {e}")
    except FileNotFoundError:
        print(f"[-] Error: Module {module_path} not found.")

if __name__ == "__main__":
    print("[*] Welcome to the Basic Pentesting Toolkit")
    print("[*] Available modules:")
    print("    1. Port Scanner (port_scanner)")
    print("    2. Network Sniffer (network_sniffer)")
    print("    3. Brute Forcer (brute_forcer)")
    print("    4. Vulnerability Scanner (vuln_scanner)")
    print("    5. Exit")

    while True:
        choice = input("Enter the number of the module to run: ")

        if choice == '1':
            run_module("port_scanner")
        elif choice == '2':
            run_module("network_sniffer")
        elif choice == '3':
            run_module("brute_forcer")
        elif choice == '4':
            run_module("vuln_scanner")
        elif choice == '5':
            print("[*] Exiting toolkit.")
            break
        else:
            print("[-] Invalid choice. Please enter a number from 1 to 5.")
