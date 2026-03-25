#!/usr/bin/env python3
"""
Wazuh Alert Log Parser
Extracts and summarises security events from Wazuh alerts.json
Author: Osama Aljahmi
"""

import json
from collections import Counter
from datetime import datetime
import os

def parse_wazuh_alerts(log_path='/var/ossec/logs/alerts/alerts.json'):
    """Extract key fields from Wazuh alerts"""
    alerts = []
    
    # Check if file exists
    if not os.path.exists(log_path):
        print(f"Error: File not found at {log_path}")
        return alerts
    
    try:
        with open(log_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:  # Skip empty lines
                    continue
                    
                try:
                    alert = json.loads(line)
                    
                    # Extract relevant fields
                    alerts.append({
                        'timestamp': alert.get('timestamp', 'N/A'),
                        'rule_id': alert.get('rule', {}).get('id', 'N/A'),
                        'rule_description': alert.get('rule', {}).get('description', 'N/A'),
                        'level': alert.get('rule', {}).get('level', 'N/A'),
                        'agent': alert.get('agent', {}).get('name', 'N/A'),
                        'location': alert.get('location', 'N/A')
                    })
                    
                except json.JSONDecodeError as e:
                    print(f"Warning: Could not parse line {line_num}: {e}")
                    continue
                    
    except Exception as e:
        print(f"Error reading file: {e}")
        return alerts
    
    print(f"Successfully parsed {len(alerts)} alerts")
    return alerts

def generate_report(alerts):
    """Create a summary report"""
    if not alerts:
        print("No alerts to analyze")
        return
    
    print("\n" + "="*50)
    print("WAZUH ALERT ANALYSIS REPORT")
    print("="*50)
    
    print(f"\nTotal alerts analyzed: {len(alerts)}")
    
    # Get time range
    timestamps = [a['timestamp'] for a in alerts if a['timestamp'] != 'N/A']
    if timestamps:
        print(f"Time range: {min(timestamps)} to {max(timestamps)}")
    
    # Top rules triggered
    rules = Counter([a['rule_description'] for a in alerts if a['rule_description'] != 'N/A'])
    print("\n📊 TOP 5 ALERT TYPES:")
    for rule, count in rules.most_common(5):
        print(f"   • {rule}: {count}")
    
    # Alerts by severity level
    levels = Counter([a['level'] for a in alerts if a['level'] != 'N/A'])
    print("\n📈 ALERTS BY SEVERITY LEVEL:")
    
    def sort_level(level):
        """Convert level to integer for sorting, handle both string and int"""
        try:
            return int(level)
        except (ValueError, TypeError):
            return 0
    
    for level in sorted(levels.keys(), key=sort_level):
        print(f"   • Level {level}: {levels[level]}")
    
    # Top agents
    agents = Counter([a['agent'] for a in alerts if a['agent'] != 'N/A'])
    print("\n💻 TOP AGENTS:")
    for agent, count in agents.most_common(3):
        print(f"   • {agent}: {count}")
    
    # Recent alerts (last 5)
    print("\n🔔 RECENT ALERTS (Last 5):")
    for alert in alerts[-5:]:
        print(f"   • [{alert['timestamp'][:19]}] {alert['rule_description']} (Level {alert['level']})")
    
    print("\n" + "="*50)

def export_to_csv(alerts, filename='wazuh_alerts.csv'):
    """Export alerts to CSV file"""
    import csv
    
    if not alerts:
        return
    
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['timestamp', 'rule_id', 'rule_description', 'level', 'agent', 'location'])
        writer.writeheader()
        writer.writerows(alerts)
    
    print(f"\n📁 Exported to {filename}")

if __name__ == "__main__":
    print("🔍 Wazuh Alert Parser Starting...")
    
    # Parse alerts
    alerts = parse_wazuh_alerts()
    
    # Generate report
    generate_report(alerts)
    
    # Optional: export to CSV
    if alerts and len(alerts) > 0:
        export_to_csv(alerts)
    
    print("\n✅ Analysis complete!")