# Application Activity Analytics Dashboard
Mini-Project C - Secure Application Development Lab, UNSIET, VBSPU Jaunpur
Author: Srijan Srivastav

Synthetic-log dashboard (Streamlit + pandas + Matplotlib) with a SQLite audit trail. Local execution only.

## Setup (Windows 11)
    python -m venv venv
    venv\Scripts\activate
    pip install -r source\requirements.txt
    python source\generate_logs.py
    streamlit run source\app.py

## Run tests
    python -m unittest discover -s source\tests -v

## Structure
- source\log_analyzer.py : parsing, validation, metrics, threshold flags
- source\audit.py        : parameterized SQLite audit of filter use
- source\app.py          : dashboard UI
- source\generate_logs.py: synthetic data generator
- data\activity_logs.csv : synthetic log (includes 6 deliberately invalid rows)
- database\audit.db      : audit trail (created automatically)

## Security controls
1. Strict row validation (allow-lists, regex, range checks); bad rows rejected safely.
2. Parameterized SQL; audit stores only filter choices, no sensitive data.
3. 2 MB upload limit, CSV only; spreadsheet-formula neutralisation on exported text.
4. Synthetic data only; no real IPs, accounts or secrets.

## Threshold
Default 15% = about 3x the ~5% baseline error rate. A flag is a prompt to investigate, not proof of an attack.