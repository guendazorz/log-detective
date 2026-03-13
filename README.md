\# Log Detective — Mini SOC Threat Detection Dashboard



Log Detective is a small security analytics project that demonstrates how authentication logs can be parsed, analyzed, and correlated to detect suspicious activity.  

The project simulates a simplified Security Operations Center (SOC) workflow: ingest logs, apply detection rules, generate alerts, and visualize the results.



The goal of the project is to better understand how log analysis and event correlation can be used to detect real-world attack patterns such as brute-force login attempts.





\## Features



\- Parse Linux authentication logs (`auth.log`)

\- Detect brute-force login attempts based on failed login patterns

\- Detect successful logins following repeated failures (possible compromise)

\- Generate structured alerts with evidence

\- Visualize attack activity through an interactive dashboard

\- Export alerts and parsed events as CSV files

\- Automated tests to validate detection logic





\## Detection Rules



\### Brute Force Detection

Triggers when multiple failed login attempts from the same IP occur within a defined time window.



\### Successful Login After Failures

Flags a successful login that occurs after repeated failed attempts from the same IP address, which can indicate credential compromise.





\## Dashboard



The project includes a Streamlit dashboard that allows users to:



\- View parsed authentication events

\- Review generated alerts

\- Adjust detection thresholds

\- Visualize login activity over time

\- Identify the most active attacking IPs





\## Screenshots



\### Dashboard Overview

!\[Dashboard Overview](docs/screenshots/dashboard\_overview.png)



\### Alerts Generated

!\[Alerts Table](docs/screenshots/alerts\_table.png)



\### Parsed Authentication Events

!\[Parsed Events](docs/screenshots/parsed\_events.png)







\## Project Structure



\## Project Structure



The repository is organized to separate data ingestion, detection logic, visualization, and testing components.



log-detective/

│

├── data/                 # Sample authentication log used for testing

│   └── sample\_auth.log

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

├── pyproject.toml        # Project dependencies and configuration

└── .gitignore



