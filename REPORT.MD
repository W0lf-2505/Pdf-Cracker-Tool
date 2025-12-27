# PDF Password Cracker Tool  
## Project Report

---

## 1. Introduction

PDF files are widely used to store and share sensitive information such as reports, invoices, legal documents, and academic materials. To protect confidentiality, PDFs often use password-based encryption. However, weak or commonly used passwords can significantly reduce the effectiveness of this protection.

This project focuses on understanding how password-protected PDFs can be tested for weak passwords in a controlled and authorized environment. The implementation demonstrates common password recovery techniques used in cybersecurity education and research to highlight the importance of strong password practices.

---

## 2. Objective

The objectives of this project are:

- To study the security implications of weak PDF passwords
- To implement dictionary-based and brute-force password recovery techniques
- To apply multithreading for performance optimization
- To understand real-world password attack workflows used in cybersecurity assessments
- To reinforce ethical and authorized testing practices

---

## 3. Scope of the Project

This project is designed strictly for:

- Educational and academic purposes
- Cybersecurity laboratory experiments
- Authorized security testing on owned or permitted PDF files

The project does **not** encourage unauthorized access to protected documents.

---

## 4. Technologies Used

- **Programming Language:** Python 3  
- **Libraries Used:**
  - `pikepdf` – handling encrypted PDF files
  - `argparse` – command-line argument parsing
  - `itertools` – password generation for brute-force attacks
  - `concurrent.futures` – multithreading support
  - `tqdm` – progress visualization

---

## 5. Methodology

The tool supports two primary password recovery techniques:

### 5.1 Dictionary Attack
- A wordlist file containing commonly used passwords is loaded
- Each password is tested against the encrypted PDF
- Multithreading is used to test multiple passwords concurrently
- Execution stops immediately once the correct password is found

### 5.2 Brute-Force Attack
- Passwords are generated dynamically using a defined character set
- Minimum and maximum password lengths are configurable
- All possible combinations within the defined constraints are tested
- Suitable only for short passwords due to exponential complexity

A global flag is used to ensure that all running threads stop once the password is successfully recovered.

---

## 6. Implementation Details

- The tool uses `argparse` to provide a flexible command-line interface
- ThreadPoolExecutor enables concurrent password attempts
- Error handling ensures stability during incorrect password attempts
- Progress bars provide real-time feedback during execution
- The tool automatically terminates further attempts when the password is found

---

## 7. Results and Testing

During testing:

- The tool successfully recovered passwords present in the provided wordlist
- Brute-force attacks worked effectively for short and simple passwords
- Multithreading significantly improved execution speed
- The tool correctly handled incorrect passwords without crashing

These results demonstrate how weak passwords can compromise document security.

---

## 8. Limitations

- Brute-force attacks are computationally expensive
- Ineffective against long or complex passwords
- Performance depends on system hardware and thread count
- Not suitable for large-scale or real-world unauthorized use

---

## 9. Ethical Considerations

⚠️ **Important Ethical Notice**

This project must only be used on PDF files that the user owns or has explicit permission to test. Unauthorized password cracking may violate legal and ethical guidelines.

Ethical hacking requires authorization, responsibility, and compliance with applicable laws.

---

## 10. Future Enhancements

Possible improvements include:

- Password strength analysis and reporting
- Time-to-crack estimation
- Improved thread coordination and optimization
- Logging results to files
- Integration with security audit frameworks

---

## 11. Learning Outcomes

Through this project, the following skills were developed:

- Understanding of PDF encryption mechanisms
- Practical exposure to password recovery techniques
- Experience with multithreading in Python
- Awareness of password security risks and defenses
- Application of ethical cybersecurity principles

---

## 12. Conclusion

The PDF Password Cracker Tool successfully demonstrates how weak passwords can undermine document security. By implementing dictionary and brute-force techniques in a controlled environment, the project emphasizes the importance of strong passwords and secure encryption practices. This project provides valuable hands-on experience in cybersecurity concepts relevant to real-world security assessments.

---

## 13. Disclaimer

This project is developed strictly for **educational purposes**.  
The author is not responsible for any misuse of this tool.
