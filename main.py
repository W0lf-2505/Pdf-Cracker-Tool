import argparse
import itertools
import string
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import pikepdf
from typing import Optional, List

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

found_password = None
found_event = None  # Use threading.Event for better control

def try_password(pdf_path: str, password: str) -> Optional[str]:
    """Attempt to open the PDF with the given password."""
    global found_password
    if found_password:
        return None
    try:
        with pikepdf.open(pdf_path, password=password):
            found_password = password
            return password
    except pikepdf.PasswordError:
        return None
    except Exception:
        return None

def load_wordlist(wordlist_path: str) -> List[str]:
    """Load passwords from wordlist file."""
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Wordlist file '{wordlist_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading wordlist: {e}")
        sys.exit(1)

def dictionary_attack(pdf_path: str, wordlist: str, threads: int, output_file: Optional[str] = None, save_unlocked: Optional[str] = None, verbose: bool = False) -> Optional[str]:
    """Perform dictionary attack."""
    global found_password
    passwords = load_wordlist(wordlist)
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(try_password, pdf_path, pw): pw for pw in passwords}
        pbar = tqdm(total=len(futures), desc="Dictionary Attack", unit="pw") if HAS_TQDM else None

        for future in as_completed(futures):
            if pbar:
                pbar.update(1)
            result = future.result()
            if result:
                elapsed = time.time() - start_time
                print(f"\n[+] Password found: {result} (in {elapsed:.2f}s)")
                if output_file:
                    save_password(output_file, result)
                if save_unlocked:
                    unlock_pdf(pdf_path, result, save_unlocked)
                return result

        if pbar:
            pbar.close()

    elapsed = time.time() - start_time
    print(f"\n[-] Password not found in wordlist (checked {len(passwords)} passwords in {elapsed:.2f}s).")
    return None

def brute_force_generator(charset: str, min_len: int, max_len: int):
    """Generator for brute-force passwords."""
    for length in range(min_len, max_len + 1):
        for pw_tuple in itertools.product(charset, repeat=length):
            yield ''.join(pw_tuple)

def brute_force_attack(pdf_path: str, charset: str, min_len: int, max_len: int, threads: int, output_file: Optional[str] = None, save_unlocked: Optional[str] = None, verbose: bool = False) -> Optional[str]:
    """Perform brute-force attack."""
    global found_password
    total_combinations = sum(len(charset) ** length for length in range(min_len, max_len + 1))
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        gen = brute_force_generator(charset, min_len, max_len)
        pbar = tqdm(total=total_combinations, desc="Brute-Force", unit="pw") if HAS_TQDM else None

        for pw in gen:
            if found_password:
                break
            futures.append(executor.submit(try_password, pdf_path, pw))
            if len(futures) >= threads * 100:  # Limit pending futures
                for future in as_completed(futures):
                    if pbar:
                        pbar.update(1)
                    result = future.result()
                    if result:
                        elapsed = time.time() - start_time
                        print(f"\n[+] Password found: {result} (in {elapsed:.2f}s)")
                        if output_file:
                            save_password(output_file, result)
                        if save_unlocked:
                            unlock_pdf(pdf_path, result, save_unlocked)
                        return result
                futures = []

        # Process remaining futures
        for future in as_completed(futures):
            if pbar:
                pbar.update(1)
            result = future.result()
            if result:
                elapsed = time.time() - start_time
                print(f"\n[+] Password found: {result} (in {elapsed:.2f}s)")
                if output_file:
                    save_password(output_file, result)
                if save_unlocked:
                    unlock_pdf(pdf_path, result, save_unlocked)
                return result

        if pbar:
            pbar.close()

    elapsed = time.time() - start_time
    print(f"\n[-] Password not found using brute-force (in {elapsed:.2f}s).")
    return None

def hybrid_attack(pdf_path: str, wordlist: str, charset: str, mutations: int, threads: int, output_file: Optional[str] = None, save_unlocked: Optional[str] = None, verbose: bool = False) -> Optional[str]:
    """Perform hybrid attack: dictionary with mutations."""
    global found_password
    base_passwords = load_wordlist(wordlist)
    mutated_passwords = set()

    # Generate mutations
    for pw in base_passwords:
        mutated_passwords.add(pw)
        # Simple mutations: add numbers, capitalize, etc.
        for i in range(mutations):
            for num in '0123456789':
                mutated_passwords.add(pw + num)
                mutated_passwords.add(num + pw)
            mutated_passwords.add(pw.capitalize())
            mutated_passwords.add(pw.upper())

    mutated_passwords = list(mutated_passwords)
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(try_password, pdf_path, pw): pw for pw in mutated_passwords}
        pbar = tqdm(total=len(futures), desc="Hybrid Attack", unit="pw") if HAS_TQDM else None

        for future in as_completed(futures):
            if pbar:
                pbar.update(1)
            result = future.result()
            if result:
                elapsed = time.time() - start_time
                print(f"\n[+] Password found: {result} (in {elapsed:.2f}s)")
                if output_file:
                    save_password(output_file, result)
                if save_unlocked:
                    unlock_pdf(pdf_path, result, save_unlocked)
                return result

        if pbar:
            pbar.close()

    elapsed = time.time() - start_time
    print(f"\n[-] Password not found in hybrid attack (checked {len(mutated_passwords)} passwords in {elapsed:.2f}s).")
    return None

def save_password(output_file: str, password: str):
    """Save the found password to a file."""
    try:
        with open(output_file, 'w') as f:
            f.write(password)
        print(f"[+] Password saved to {output_file}")
    except Exception as e:
        print(f"[-] Error saving password: {e}")

def unlock_pdf(pdf_path: str, password: str, output_path: str):
    """Unlock and save the PDF without password."""
    try:
        with pikepdf.open(pdf_path, password=password) as pdf:
            pdf.save(output_path)
        print(f"[+] Unlocked PDF saved to {output_path}")
    except Exception as e:
        print(f"[-] Error unlocking PDF: {e}")

def main():
    parser = argparse.ArgumentParser(description="Advanced PDF Password Cracker Tool")
    parser.add_argument("pdf", help="Path to the password-protected PDF file")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-b", "--brute", action="store_true", help="Enable brute-force attack")
    parser.add_argument("-hy", "--hybrid", action="store_true", help="Enable hybrid attack (dictionary + mutations)")
    parser.add_argument("-min", "--minlen", type=int, default=1, help="Minimum password length for brute-force")
    parser.add_argument("-max", "--maxlen", type=int, default=4, help="Maximum password length for brute-force")
    parser.add_argument("-c", "--charset", default=string.ascii_lowercase, help="Character set for brute-force")
    parser.add_argument("-m", "--mutations", type=int, default=1, help="Number of mutation levels for hybrid attack")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads")
    parser.add_argument("-o", "--output", help="Output file to save found password")
    parser.add_argument("-u", "--unlock", help="Output path to save unlocked PDF")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if not os.path.isfile(args.pdf):
        print("[-] PDF file not found.")
        sys.exit(1)

    global found_password
    found_password = None

    if args.hybrid and not args.wordlist:
        print("[-] Hybrid attack requires a wordlist.")
        sys.exit(1)

    if args.wordlist and not args.hybrid:
        result = dictionary_attack(args.pdf, args.wordlist, args.threads, args.output, args.unlock, args.verbose)
    elif args.brute:
        result = brute_force_attack(args.pdf, args.charset, args.minlen, args.maxlen, args.threads, args.output, args.unlock, args.verbose)
    elif args.hybrid:
        result = hybrid_attack(args.pdf, args.wordlist, args.charset, args.mutations, args.threads, args.output, args.unlock, args.verbose)
    else:
        print("[-] Please provide a wordlist (-w), enable brute-force (-b), or hybrid attack (-hy)")

if __name__ == "__main__":
    main()