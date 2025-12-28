# PDF Password Cracker Tool (Python)

## Overview
The **PDF Password Cracker Tool** is a Python-based cybersecurity utility designed to recover passwords from password-protected PDF files in controlled and authorized environments.
The project demonstrates common password recovery techniques used in cybersecurity research to highlight the risks of weak passwords.

This tool is intended **strictly for educational and ethical purposes**, such as academic projects, penetration testing labs, and authorized security assessments.

---

## Features
- Dictionary-based password attack
- Brute-force password attack
- Multithreaded execution for faster attempts
- Real-time progress visualization
- Automatic termination once the password is found
- Flexible command-line interface

---

## Technologies Used
- Python 3
- pikepdf
- argparse
- itertools
- concurrent.futures
- tqdm

---

## How It Works

### Dictionary Attack
- Reads passwords from a wordlist file
- Tries each password against the encrypted PDF
- Stops immediately if the correct password is found

### Brute-Force Attack
- Generates password combinations using a defined character set
- Supports configurable minimum and maximum password length
- Uses multithreading for faster execution

---

## Usage

### General Syntax
```bash
python main.py <pdf_file> [options]
Dictionary Attack Example
bash
Copy code
python main.py protected.pdf -w wordlist.txt -t 8
Brute-Force Attack Example
bash
Copy code
python main.py protected.pdf -b --minlen 1 --maxlen 4 --charset abc123 -t 4
Command-Line Arguments
Argument	Description
pdf	Path to the protected PDF file
-w, --wordlist	Path to wordlist file
-b, --brute	Enable brute-force attack
--minlen	Minimum password length
--maxlen	Maximum password length
--charset	Character set for brute-force
-t, --threads	Number of threads

Limitations
Brute-force attacks are time and resource intensive

Ineffective against strong or long passwords

Performance depends on hardware and thread count

Designed only for small-scale testing

Ethical Considerations
⚠️ IMPORTANT

This tool must only be used on:

PDF files you own

Files you have explicit permission to test

Unauthorized use against third-party documents may be illegal and unethical.

Learning Outcomes
Understanding PDF encryption mechanisms

Exposure to password attack strategies

Practical experience with multithreading in Python

Awareness of secure password practices

Disclaimer
This project is developed strictly for educational purposes.
The author is not responsible for any misuse of this tool.
