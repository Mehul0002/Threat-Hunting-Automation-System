# Threat-Hunting Automation System - Testing TODO

## Completed ✅
- [x] Create modular project structure
- [x] Implement GUI with Tkinter
- [x] Build log parser for Windows/Linux
- [x] Create IOC detector with sample data
- [x] Implement Sigma rule engine
- [x] Add behavior analyzer
- [x] Set up SQLite database
- [x] Create report generator
- [x] Add sample logs and rules
- [x] Fix import errors

## Testing Tasks 🔄

### GUI Testing
- [ ] Launch GUI application (`python gui.py`)
- [ ] Test file selection dialog
- [ ] Verify OS type radio buttons (Windows/Linux)
- [ ] Check "Run Threat Hunt" button functionality
- [ ] Test real-time output panel updates
- [ ] Verify IOC matches table display
- [ ] Check severity indicator updates
- [ ] Test report generation buttons (TXT/PDF/JSON)

### Log Parsing Testing
- [ ] Test Windows log parsing with sample data
- [ ] Test Linux log parsing with sample data
- [ ] Verify parsed log structure (JSON format)
- [ ] Check timestamp normalization
- [ ] Validate event ID extraction

### IOC Detection Testing
- [ ] Test hardcoded IOC matching
- [ ] Verify IP address detection
- [ ] Check domain matching
- [ ] Test hash detection (MD5/SHA256)
- [ ] Validate process name matching
- [ ] Test registry key detection (Windows)

### Sigma Rule Testing
- [ ] Test rule loading from YAML files
- [ ] Verify credential dumping rule matching
- [ ] Check PowerShell abuse detection
- [ ] Test brute force login rule
- [ ] Validate rule severity levels

### Behavior Analysis Testing
- [ ] Test failed login detection
- [ ] Verify privilege escalation alerts
- [ ] Check unusual process execution
- [ ] Test persistence mechanism detection
- [ ] Validate behavior summary generation

### Database Testing
- [ ] Test log storage in SQLite
- [ ] Verify IOC insertion
- [ ] Check alert storage
- [ ] Test data retrieval functions
- [ ] Validate database schema

### Report Generation Testing
- [ ] Generate TXT report
- [ ] Test PDF report creation
- [ ] Verify JSON report output
- [ ] Check report content accuracy
- [ ] Validate recommendations section

### Integration Testing
- [ ] Run full threat hunt workflow
- [ ] Test end-to-end processing
- [ ] Verify error handling
- [ ] Check performance with sample data
- [ ] Validate logging output

## Known Issues 🐛
- [ ] GUI may require tkinter installation on some systems
- [ ] PDF generation requires reportlab
- [ ] Sigma rule parsing may need refinement for complex rules

## Next Steps 📋
1. Install dependencies: `pip install -r requirements.txt`
2. Run GUI: `python gui.py`
3. Test with sample logs in `sample_logs/` directory
4. Generate and review reports
5. Address any issues found during testing
