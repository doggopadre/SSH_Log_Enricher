# SSH_Log_Enricher
Small script to enrich SSH logs for Malicious IP addresses with failed SSH login attepmts against VirusTotal.

### Usage
- Usage is simple, just do python3 enricher.py
- Make sure that you replace the ssh_logsd.log file with your actual log file you want to enrich.
- Also make sure you export your VirusTotal API key "export VT_KEY=your-api-key-here"
