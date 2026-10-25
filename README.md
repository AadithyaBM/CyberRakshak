# CyberRakshak

### Detect the Threat. Understand the Attack. Protect the User.

**CyberRakshak** is a Python-based cybersecurity educational platform focused on URL risk analysis, phishing-pattern detection, authentication security demonstrations, and defense validation.

The project demonstrates how local security rules can identify suspicious URL characteristics and how authentication controls can be tested in a controlled environment.

> **Disclaimer:** CyberRakshak is an educational prototype. Its heuristic URL scores are not probabilities, and its validation results do not certify an application as secure.

---

## 1. Project Objectives

* Analyze URL structures for potentially suspicious characteristics.
* Identify selected lookalike-domain and suspicious-subdomain patterns.
* Demonstrate password hashing and verification.
* Demonstrate OTP expiration, attempt limits, and one-time use.
* Demonstrate login rate limiting.
* Validate selected authentication security controls.
* Provide an interactive dashboard for security demonstrations and reports.

## 2. Features

### URL Investigation

* URL syntax validation and normalization.
* Detection of IP-address hostnames.
* Detection of potentially deceptive `@` usage.
* Identification of unusually long URLs and excessive subdomain levels.
* Screening for selected lookalike-domain patterns.
* Detection of selected brand names in subdomains.
* Identification of known URL-shortening services.
* Detection of potentially sensitive URL keywords.
* Warnings for HTTP connections and non-standard ports.
* Heuristic risk scores and recommendations.

### Authentication Security Lab

* Password hashing using PBKDF2-HMAC-SHA256.
* Random salt generation.
* Password verification using constant-time comparison.
* Simulated six-digit OTP generation.
* OTP expiration, failed-attempt limits, and one-time use.
* In-memory login rate limiting.

### Defense Validation

* Password hashing and verification checks.
* OTP security checks.
* Login rate-limiting checks.
* Summary of validation results.

### Simulation Lab

Provides controlled, fictional phishing-awareness scenarios for educational demonstrations.

### Reporting

The project includes report-generation functionality for summarizing security analysis and validation results.

---

## 3. Technology Stack

* **Programming language:** Python
* **Dashboard:** Streamlit
* **Data handling:** Pandas
* **Visualization:** Plotly
* **HTTP library:** Requests
* **Testing:** Pytest
* **Version control:** Git

---

## 4. Project Structure

```text
CyberRakshak/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── engine/
│   ├── __init__.py
│   ├── url_analyzer.py
│   └── threat_intelligence.py
├── security/
│   ├── __init__.py
│   ├── auth_security.py
│   └── defense_validator.py
├── simulation/
│   ├── __init__.py
│   └── phishing_simulator.py
├── reports/
│   └── report_generator.py
└── tests/
    ├── test_url_analyzer.py
    ├── test_threat_intelligence.py
    ├── test_auth_security.py
    ├── test_phishing_simulator.py
    ├── test_defense_validator.py
    ├── test_report_generator.py
    ├── test_end_to_end.py
    └── evaluate_url_detection.py
```

---

## 5. Installation

### Prerequisites

* Python installed on your computer.
* Git.
* Visual Studio Code or another Python-compatible editor.

### Step 1: Open the project directory

```powershell
cd C:\Users\aadit\CyberRakshak
```

### Step 2: Activate the virtual environment

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install dependencies

```powershell
python -m pip install -r requirements.txt
```

---

## 6. Run the Application

Start the Streamlit dashboard:

```powershell
python -m streamlit run app.py
```

Streamlit will display a local address in the terminal. Open that address in your browser.

---

## 7. Run the Automated Tests

Run the complete test suite:

```powershell
python -m pytest -v
```

Run URL analyzer tests:

```powershell
python -m pytest tests/test_url_analyzer.py -v
```

Run authentication tests:

```powershell
python -m pytest tests/test_auth_security.py -v
```

Run defense validation tests:

```powershell
python -m pytest tests/test_defense_validator.py -v
```

Run the URL evaluation script:

```powershell
python tests/evaluate_url_detection.py
```

The evaluation script writes detailed results to `url_evaluation_results.csv`.

---

## 8. Current Testing Results

During development, the following results were reported:

| Test group                     | Reported result |
| ------------------------------ | --------------: |
| URL analyzer tests             |       27 passed |
| Authentication security tests  |       28 passed |
| Defense validator tests        |        9 passed |
| Complete project test suite    |       78 passed |
| URL evaluation validity checks |    21/21 passed |
| Defense validation groups      |      3/3 passed |

These results reflect the development runs reported for this project. Rerun the commands above to verify the current state of the code.

The URL evaluation is a rule-coverage and behavior check, not a real-world phishing accuracy benchmark.

---

## 9. Important Security Limitations

* URL analysis uses local heuristics.
* URL analysis does not visit the submitted URL or follow redirects.
* DNS, WHOIS, SSL certificate, and HTML inspection should not be described as implemented unless those capabilities are separately added and verified.
* The threat-intelligence module should not be described as providing live external verification unless a provider is configured.
* A low URL risk score does not guarantee that a URL is safe.
* A warning indicator does not prove that a URL is malicious.
* Selected lookalike-domain rules cover only a limited set of brands and character substitutions.
* OTP codes are returned to the caller in this educational implementation.
* Login rate-limiting state is stored in memory and is not a distributed production control.
* The authentication and defense validation modules are demonstrations, not a complete production authentication service.

Do not use the project as the sole basis for real-world security decisions.

---

## 10. Ethical Use

CyberRakshak is intended for cybersecurity education, controlled testing, and defensive security awareness.

Use it only on systems and data you are authorized to test. The simulation features are intended for safe demonstrations and should not be used to collect real credentials.

---

## 11. Future Improvements

Possible future work includes:

* Expanding URL detection tests with carefully labeled datasets.
* Evaluating detection coverage and false-positive behavior.
* Adding an explicitly configured threat-intelligence provider.
* Implementing real DNS and certificate inspection with appropriate safeguards.
* Improving report exports and evaluation summaries.
* Adding more authentication edge-case tests.
* Preparing reproducible project demonstrations and documentation.

---

## 12. Project Summary

CyberRakshak combines URL heuristic analysis, phishing-awareness simulations, authentication security demonstrations, and defense validation in a Python-based dashboard.

Its purpose is to demonstrate security concepts, identify selected warning signs, and make defensive testing easier to understand.
