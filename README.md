# AxisGG

AxisGG is a Python script designed to bruteforce the HTTP Basic Authentication used by AXIS cameras while being connected to the Tor network for anonymity.

## Usage

To use AxisGG, you need to have Python installed on your system along with the required dependencies. You can install the dependencies using pip:

```bash
pip install -r requirements.txt
```

Once the dependencies are installed, you can run the script with the following command:

```bash
python script.py --url <URL> --usernames-wordlist <path_to_usernames_wordlist> --passwords-wordlist <path_to_passwords_wordlist>
```

Replace `<URL>` with the URL of the AXIS camera you want to check, `<path_to_usernames_wordlist>` with the path to the file containing the list of usernames, and `<path_to_passwords_wordlist>` with the path to the file containing the list of passwords.

## Dependencies

- termcolor: For colored console output
- tqdm: For displaying progress bars
- requests: For sending HTTP requests
- urllib: For URL parsing

## Notes

- This script must be executed while connected to the Tor network.
- AxisGG relies on wordlists of usernames and passwords to attempt authentication. Make sure to provide comprehensive wordlists for better results.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
