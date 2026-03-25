# Wazuh Alert Log Parser

A Python script to parse Wazuh SIEM alerts and generate security event reports from real alerts.

## 📊 Sample Output

From 413 alerts generated during Wazuh deployment:
==================================================
WAZUH ALERT ANALYSIS REPORT
==================================================

Total alerts analyzed: 413
Time range: 2026-03-16T00:08:20.847+0000 to 2026-03-16T14:06:58.897+0000

📊 TOP 5 ALERT TYPES:

• Apparmor DENIED: 178
• File added to the system.: 84
• PAM: Login session opened.: 37
• PAM: Login session closed.: 35
• Successful sudo to ROOT executed.: 31

📈 ALERTS BY SEVERITY LEVEL:

• Level 3: 289
• Level 4: 1
• Level 5: 89
• Level 7: 32
• Level 8: 2


## 🔧 How It Works

1. Reads Wazuh `alerts.json` file
2. Parses each JSON alert
3. Extracts timestamp, rule ID, description, severity level
4. Generates summary report with top alert types

## 🚀 Usage

```bash
sudo python3 wazuh-alert-parser.py
