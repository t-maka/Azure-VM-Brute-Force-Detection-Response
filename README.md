# 🛡️ Azure VM Brute-Force Detection & Response  

 **Incident Response Using Microsoft Sentinel, MITRE ATT&CK & NIST 800-61**

## 📌 Scenario:
Nine different **Azure-based virtual machines** were potentially targeted by **brute-force login attempts** originating from **eight distinct public IP addresses** on the internet.

As a **Security Analyst**, I initiated an investigation to determine whether these attempts constituted a brute-force attack and to contain and remediate any potential compromise.


## 🎯 Objective

Apply the **NIST SP 800-61 (Rev. 2) Incident Response Framework** alongside relevant **MITRE ATT&CK** techniques to detect, analyze, and mitigate brute-force attempts targeting Azure VMs.


## 📊 Timeline Summary & Findings 


### 🔔 Part 1: Detection — Brute-Force Attempt Alert Rule

Analyzed `LogonFailed` events from the `DeviceLogonEvents` table over a 5-hour period to detect brute-force attempts:

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10
```
![VM brute forcing](https://github.com/user-attachments/assets/2e0e8b6c-56d9-475e-8768-bf18276a91c9)

---

### 🚨 Part 2: Alert & Incident Generation
A custom analytics rule was created in Microsoft Sentinel.
- Once triggered, it:
  - Generated an alert
  - Created an incident
  - Produced an automated investigation graph
    
 ![MS Sentinel one inceident investigation](https://github.com/user-attachments/assets/69a35c17-9710-4219-911a-8f6aed30b70b)


---

### 🔍 Part 3: Investigation
Validated that none of the brute-force attempts led to successful logins:

```kql
DeviceLogonEvents
| where RemoteIP in (
    "80.66.88.30", "149.50.96.98", "175.101.32.139",
    "189.231.171.165", "80.64.18.199", "112.78.133.134",
    "156.238.240.254", "188.19.116.226"
)
| where ActionType != "LogonFailed"
```
✅ Result: No successful logons from any suspicious IPs.

---

### 🛡️ Part 4: Containment & Mitigation
- ✅ Isolated all 9 affected VMs using Microsoft Defender for Endpoint (MDE)
- ✅ Initiated anti-malware scans on all VMs
- ✅ Updated NSG rules to:
  - Block all RDP from public internet
  - Allow RDP access only from trusted IP address
📌 Policy recommendation:
- Restrict RDP on all VMs going forward or use Azure Bastion
---

### 🔁 NIST 800-61 Incident Response Lifecycle (Step-by-Step)

The following is a step-by-step overview of our scenario aligned with the NIST 800-61 Incident Response Lifecycle.

| NIST Phase             | Action                                                         | Tools Used                         | MITRE ATT\&CK Mapping                      |
| ---------------------- | -------------------------------------------------------------- | ---------------------------------- | ------------------------------------------ |
| **1. Preparation**     | Harden NSGs; recommend restricted RDP policies                 | Azure NSG, Azure Policy            | N/A                                        |
| **2. Detection**       | Query failed logons to identify brute-force attempts           | Sentinel, KQL, DeviceLogonEvents   | `T1110`, `T1110.001`, `T1110.003`          |
| **3. Analysis**        | Investigate alerts and verify absence of successful logons     | Sentinel, KQL, Investigation Graph | `TA0006 – Credential Access`               |
| **4. Containment**     | Isolate infected VMs and block attacker access                 | MDE Isolation, NSG reconfiguration | `TA0001 – Initial Access (mitigated)`      |
| **5. Eradication**     | Run malware scans across all VMs                               | Microsoft Defender Antivirus       | `T1059`, `T1027` (if persistence is found) |
| **6. Recovery**        | Restore access via secure channels (e.g., trusted IP, Bastion) | Azure NSG, Bastion (optional)      | N/A                                        |
| **7. Lessons Learned** | Document response, refine detection rules, enforce RDP policy  | Policy-as-Code                     | N/A                                        |

---

### 🧠 MITRE ATT&CK Techniques Mapped
- T1110 – Brute Force
  - T1110.001 – Password Guessing
  - T1110.003 – Password Spraying
- TA0006 – Credential Access
- TA0001 – Initial Access

---

📝 Note: This incident was detected and mitigated before any compromise occurred. The investigation followed structured incident response procedures, leveraging Microsoft Sentinel, Defender for Endpoint, and best practices from MITRE ATT&CK and NIST 800-61.

## Created By:
- **Author Name**: Tinan Makadjibeye  
- **Author Contact**: [LinkedIn profile](https://www.linkedin.com/in/makadjibeye-tinan)  
- **Date**: June 2025
  
---
