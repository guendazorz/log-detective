# Log Detective — Mini SOC-Style Threat Detection Dashboard

Log Detective is a cybersecurity analytics project that demonstrates how authentication logs can be parsed, analyzed, and correlated to detect suspicious activity.

The project simulates a simplified **Security Operations Center (SOC)** workflow:

1. Ingest authentication logs
2. Parse events into structured data
3. Apply detection rules
4. Generate alerts
5. Visualize activity in an interactive dashboard

The goal of the project is to better understand how **log analysis and event correlation** can reveal real-world attack patterns such as brute-force login attempts.

---

# Features

* Parse Linux authentication logs (`auth.log`)
* Detect **brute-force login attempts**
* Detect **successful logins following repeated failures**
* Generate structured alerts with evidence
* Visualize attack activity in an interactive dashboard
* Export alerts and parsed events as CSV files
* Automated tests for detection logic

---

# Detection Rules

## Brute Force Detection

Triggers when multiple failed login attempts from the same IP occur within a defined time window.

This behavior is commonly associated with **password guessing or brute-force attacks**.

---

## Successful Login After Failures

Flags a successful login that occurs after repeated failed login attempts from the same IP address.

This pattern may indicate:

* Credential compromise
* Successful brute-force attack
* Account takeover

---

# Dashboard

The project includes a **Streamlit dashboard** that allows users to:

* View parsed authentication events
* Review generated alerts
* Adjust detection thresholds
* Visualize login activity over time
* Identify the most active attacking IPs

---

# Screenshots

## Dashboard Overview

![Dashboard Overview](https://github.com/guendazorz/log-detective/blob/main/docs/screenshots/dashboard_overview.png)

## Alerts Generated

![Alerts Table](https://github.com/guendazorz/log-detective/blob/main/docs/screenshots/alerts_table.png)

## Parsed Authentication Events

![Parsed Events](https://github.com/guendazorz/log-detective/blob/main/docs/screenshots/parsed_events.png)

---

# Tech Stack

* Python
* Pandas
* Streamlit
* Matplotlib
* Pytest

---

# Project Structure

The repository is organized to separate data ingestion, detection logic, visualization, and testing components.

```
log-detective/

├── data/                 # Sample authentication log used for testing
│   └── sample_auth.log
│
├── src/                  # Core application code
│   ├── parser.py         # Parses Linux auth.log entries into structured events
│   ├── detections.py     # Detection rules (brute force, success after failures)
│   ├── charts.py         # Visualization functions
│   ├── run.py            # CLI pipeline to run detections and export results
│   └── app.py            # Streamlit dashboard
│
├── tests/                # Unit tests for parser and detection logic
│
├── docs/
│   └── screenshots/      # Images used in the README
│
├── README.md             # Project documentation
├── pyproject.toml        # Project dependencies
└── .gitignore
```

---

# Installation

Clone the repository:

```
git clone https://github.com/guendazorz/log-detective.git
cd log-detective
```

Create and activate a virtual environment:

```
python -m venv .venv
```

Windows:

```
.venv\Scripts\activate
```

macOS / Linux:

```
source .venv/bin/activate
```

Install dependencies:

```
pip install -r requirements.txt
```

---

# Running the Detection Pipeline

Run the log analysis pipeline:

```
python -m src.run
```

This will:

* Parse authentication logs
* Run detection rules
* Generate alerts
* Export results

---

# Running the Dashboard

Start the Streamlit dashboard:

```
set PYTHONPATH=.
streamlit run src/app.py
```

The dashboard will open in your browser.

---

# Running Tests

Run automated tests with:

```
pytest
```

---

# Future Improvements

Possible future enhancements include:

* Password spraying detection
* Mapping detections to **MITRE ATT&CK techniques**
* Support for additional log sources
* Alert severity scoring
* Integration with SIEM pipelines

---

# What This Project Demonstrates

This project highlights practical security engineering concepts such as:

* Log parsing and normalization
* Event correlation
* Detection rule design
* Security data visualization
* Basic SOC-style monitoring workflows
