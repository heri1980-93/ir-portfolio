IR Portfolio — DFIR Samples


Included
- yara/my_suspicious_rule.yar — Example YARA rule detecting obfuscated PowerShell and suspicious payload names.
- splunk/detect_lateral_movement.savedsearch — Splunk saved search (query + notes) to detect anomalous authentication/lateral movement patterns.

How to use

YARA rule
1. Install YARA (or yara-python). Example (Python): pip install yara-python
2. Test the rule against files: yara -r yara/my_suspicious_rule.yar /path/to/sample_files
3. Review matches and include sample screenshots in your GitHub README.

Splunk saved search
- To import the search into Splunk: open Settings → Searches, Reports, and Alerts → New Report. Paste the search query from splunk/detect_lateral_movement.savedsearch and set schedule (recommended: every 15 minutes) and alert actions.
- Tweak index names and field names to match the target environment (index=security, sourcetype=WinEventLog:Security, etc.).
.

Contact
Heriberto Hernandez Garduno — herib26@gmail.com

License
Public domain sample (use at your own risk)

Suggested commit commands (PowerShell):
```
git init
git add .
git commit -m "Initial DFIR portfolio: YARA rule and Splunk saved search"
git branch -M main
git remote add origin https://github.com/<yourusername>/ir-portfolio.git
git push -u origin main
```

Notes

- Avoid including any real sensitive logs or PII in public repos. Use synthetic or red-team-style sample data.
