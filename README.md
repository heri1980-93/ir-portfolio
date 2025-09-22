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

Demonstration tips
- Include a short write-up for each artifact: what it detects, false-positive considerations, how to tune it for a real environment, and a short playbook for containment/remediation.
- Add a small sample dataset or screenshots showing the rule/search firing — this helps recruiters and hiring managers verify your hands-on skill.

Contact
Heriberto Hernandez Garduno — herib26@gmail.com

License
Public domain sample (use at your own risk)

Publishing to GitHub
- Create a new repository (e.g., heriberto/ir-portfolio) and push this folder. Include a short `README.md` describing each artifact 
- Add a `samples/` directory with screenshots or minimal sample logs showing the rules/search firing to strengthen credibility.
- Use GitHub Pages or a short portfolio README to surface key artifacts: YARA rule, Splunk saved search, and a 1-page DFIR write-up.

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