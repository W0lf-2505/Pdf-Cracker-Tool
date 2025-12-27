import argparse
import itertools
import string
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import pikepdf
from tqdm import tqdm

found = False  # Global flag to stop all threads if password is found

# Attempt to open the PDF using a password
def try_password(pdf_path, password):
    global found
    if found:
        return None
    try:
        with pikepdf.open(pdf_path, password=password):
            found = True
            return password
    except pikepdf.PasswordError:
        return None
    except Exception as e:
        return None

# Read passwords from wordlist
def load_wordlist(wordlist_path):
    with open(wordlist_path, 'r', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

# Generate passwords (brute-force)
def brute_force_generator(charset, min_len, max_len):
    for length in range(min_len, max_len + 1):
        for pw in itertools.product(charset, repeat=length):
            yield ''.join(pw)

# Crack with dictionary
def dictionary_attack(pdf_path, wordlist, threads):
    passwords = load_wordlist(wordlist)
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(try_password, pdf_path, pw): pw for pw in passwords}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Trying passwords"):
            result = future.result()
            if result:
                print(f"\n[+] Password found: {result}")
                return
    print("\n[-] Password not found in wordlist.")

# Crack with brute-force
def brute_force_attack(pdf_path, charset, min_len, max_len, threads):
    gen = brute_force_generator(charset, min_len, max_len)
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for pw in tqdm(gen, desc="Brute-forcing"):
            if found:
                break
            futures.append(executor.submit(try_password, pdf_path, pw))
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"\n[+] Password found: {result}")
                return
                
    if not found:
        print("\n[-] Password not found using brute-force.")

# Main function
def main():
    parser = argparse.ArgumentParser(description="PDF Password Cracker Tool")
    parser.add_argument("pdf", help="Path to the password-protected PDF file")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file (optional)")
    parser.add_argument("-b", "--brute", action="store_true", help="Enable brute-force attack")
    parser.add_argument("-min", "--minlen", type=int, default=1, help="Minimum password length")
    parser.add_argument("-max", "--maxlen", type=int, default=4, help="Maximum password length")
    parser.add_argument("-c", "--charset", default=string.ascii_lowercase, help="Character set for brute-force")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads")

    args = parser.parse_args()

    if not os.path.isfile(args.pdf):
        print("[-] PDF file not found.")
        return

    if args.wordlist:
        if not os.path.isfile(args.wordlist):
            print("[-] Wordlist file not found.")
            return
        dictionary_attack(args.pdf, args.wordlist, args.threads)
    elif args.brute:
        brute_force_attack(args.pdf, args.charset, args.minlen, args.maxlen, args.threads)
    else:
        print("[-] Please provide a wordlist or enable brute-force with -b")

if __name__ == "__main__":
    main()