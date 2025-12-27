# Threat-Hunting Automation System

A comprehensive GUI-based threat-hunting automation system built with Python and Tkinter.

## Features

- **Log Parsing**: Supports Windows Security logs and Linux auth/syslog
- **IOC Detection**: Hardcoded and extensible IOC database
- **Sigma Rule Engine**: YAML-based rule matching
- **Behavior Analysis**: Detects brute force, privilege escalation, unusual processes
- **SQLite Database**: Stores logs, IOCs, and alerts
- **Report Generation**: TXT, PDF, and JSON reports
- **GUI Interface**: User-friendly Tkinter interface

## Installation

1. Install Python 3.10+
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the GUI:
   ```bash
   python gui.py
   ```

2. Select a log file (use sample logs in `sample_logs/` for testing)
3. Choose OS type (Windows/Linux)
4. Click "Run Threat Hunt"
5. View results in the output panel and IOC table
6. Generate reports as needed

## Project Structure

```
threat_hunter/
├── gui.py                 # Main GUI application
├── log_parser.py          # Log parsing logic
├── ioc_detector.py        # IOC matching
├── sigma_engine.py        # Sigma rule processing
├── behavior_analyzer.py   # Behavioral analysis
├── database.py            # SQLite database operations
├── report_generator.py    # Report generation
├── utils.py               # Helper functions and logging
├── sample_logs/           # Sample log files
├── sigma_rules/           # Sigma rule definitions
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

## Sample Data

- **Windows Logs**: `sample_logs/windows_security.log`
- **Linux Logs**: `sample_logs/linux_auth.log`
- **Sigma Rules**: `sigma_rules/` directory

## Security Note

This tool is designed for defensive cybersecurity purposes only. It should not be used for offensive activities or malware creation.

## Contributing

1. Follow Python best practices
2. Add type hints
3. Include error handling
4. Update documentation

## License

This project is for educational and defensive security purposes.
