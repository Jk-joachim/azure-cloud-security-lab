# azure-cloud-security-lab
This project demonstrates how to design and implement a secure cloud environment in Microsoft Azure using best practices in identity management, network security, monitoring, and threat detection.

## 🎯 Objectives
- Implement secure Identity & Access Management
- Build segmented network architecture
- Deploy and harden a Linux VM
- Secure Azure Storage
- Enable monitoring and logging
- Integrate SIEM using Microsoft Sentinel
- Simulate and respond to security incidents

---

## 🏗️ Architecture
![Architecture](screenshots/project_Architecture.png)

---

🔐 1. Identity & Access Management

### 🛠️ Steps

#### Create User
1. Go to Microsoft Entra ID → Users → New user  
2. Enter username, name, password  
3. Click Create  

#### Create Group
1. Microsoft Entra ID → Groups → New group  
2. Type: Security  
3. Name: SecurityTeam  
4. Add user  

#### Assign Roles
1. Subscriptions → Access Control (IAM)  
2. Add role assignment  
3. Assign:
   - User Administrator  
   - Contributor  

#### Enable MFA
1. Entra ID → Security → Conditional Access  
2. Create policy → Require MFA  

---

🌐 2. Network Security

### 🛠️ Steps

#### Create VNet
1. Virtual Networks → Create  
2. Address space: 192.168.0.0/16  

#### Create Subnets
- Public: 192.168.1.0/24  
- Private: 192.168.2.0/24  

#### Configure NSG
- Allow SSH (22) from your IP  
- Deny all others  

📸 Screenshot:  
![Inbound Rule](screenshots/inbound_rule.png)

---

🖥️ 3. Virtual Machine Hardening

### 🛠️ Steps

1. Create Linux VM (Ubuntu)  
2. Select SSH key authentication  
3. Place in VNet  

### 🔐 Hardening

'''bash
sudo nano /etc/ssh/sshd_config
Set:
PermitRootLogin no
PasswordAuthentication no
sudo apt update && sudo apt upgrade -y

📸 Screenshot:  
![VM Hardening](screenshots/vmhardening.png)

---

💾 4. Secure Storage
### 🛠️ Steps
1. Create Storage Account
2. Disable public access
3. Enable HTTPS only
4. Disable anonymous access

📸 Screenshot:
![Storage](screenshots/storageaccount.png)

---

📊 5. Logging & Monitoring
### 🛠️ Steps
1. Create Log Analytics Workspace
2. Install Azure Monitor Agent
3. Configure Data Collection Rule
4. Enable Syslog (auth, authpriv)

📸 Screenshot:
![Syslog DCR](screenshots/syslogDCR.png)

---

🛡️ 6. Threat Detection
### 🛠️ Steps
1. Enable Microsoft Defender for Cloud
2. Turn on Defender for Servers
3. Review recommendations
4. Fix:
- Open ports
- Missing updates

---

🧠 7. SIEM Setup (Microsoft Sentinel)
### 🛠️ Steps
1. Add Log Analytics Workspace to Sentinel
2. Enable Data Connectors
3. Create detection rule
- 🔍 Detection Query
Syslog
| where SyslogMessage has_any ("Invalid user", "Failed publickey", "Connection closed")
| extend SourceIP = extract(@"([0-9]{1,3}(\.[0-9]{1,3}){3})", 1, SyslogMessage)
| summarize 
    Attempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleMessage = any(SyslogMessage)
    by SourceIP, Computer, bin(TimeGenerated, 5m), _ResourceId
| where Attempts > 5


📸 Screenshot:
![Syslog DCR](screenshots/syslogDCR.png)

---

🚨 8. Incident Simulation
- 🧪 Actions
- Attempt multiple failed SSH logins
- Access restricted ports
- 🔍 Investigation
Syslog
| where SyslogMessage has_any ("Invalid user", "Failed publickey", "Connection closed")

📸 Screenshot:
![Incident](screenshots/Incident_Alert.png)


📸 Screenshot:
![Simulation](screenshots/attemptedloginlog.png)

---

🚫 Response
- Identified attacker IP
- Blocked using NSG rule
- 🔁 Incident Response Workflow

Attack → Detection → Investigation → Response

---

✅ Key Security Principles
- Least Privilege
- Defense in Depth
- Network Segmentation
- Monitoring & Alerting


---

# 🧠 9. MITRE ATT&CK Mapping

To align the lab with industry-standard threat detection frameworks, simulated attacks were mapped to the MITRE ATT&CK Framework.

## T1110 – Brute Force

### Description
Repeated login attempts to gain unauthorized access.

### Simulation
Multiple failed SSH authentication attempts against the Azure Linux VM.

### Detection

```kusto
Syslog
| where SyslogMessage contains "Failed"
| summarize Attempts=count() by bin(TimeGenerated, 5m)
```

### Response

- Investigated source IP
- Blocked malicious IP using NSG
- Reviewed authentication logs

---

## T1078 – Valid Accounts

### Description

Use of legitimate credentials to gain unauthorized or excessive access.

### Simulation

Authentication using a valid Azure user account created in Microsoft Entra ID.

### Detection

```kusto
SigninLogs
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress
```

### Response

- Enforced MFA
- Reviewed user permissions
- Applied Least Privilege principles

---

## T1190 – Exploit Public-Facing Application

### Description

Attackers target internet-facing services to gain initial access.

### Simulation

Exposed SSH service through Azure NSG and validated exposure using network reconnaissance.

### Detection

- Microsoft Defender for Cloud recommendations
- Security posture assessments
- NSG exposure review

### Response

- Restricted inbound access
- Reduced attack surface
- Updated NSG rules

---

## MITRE ATT&CK Summary

| Technique | Name | Detection | Response |
|------------|------------|------------|------------|
| T1110 | Brute Force | Sentinel Analytics Rule | Block IP |
| T1078 | Valid Accounts | Sign-In Monitoring | MFA + Access Review |
| T1190 | Public-Facing Application | Defender for Cloud | Restrict NSG Rules |

---

# 🌐 10. Cyber Threat Intelligence (CTI)

This lab was extended with Cyber Threat Intelligence capabilities to identify and investigate known malicious indicators.

## Threat Intelligence Integration

### Threat Intelligence Watchlist

Created a custom watchlist in Microsoft Sentinel containing known malicious IP addresses.

Example:

```csv
IPAddress
192.168.1.100
8.8.8.8
1.1.1.1
```

📸 Screenshot:
![Watchlist](screenshots/threat_intelligence_watchlist.png)

---

## Threat Intelligence Detection Rule

```kusto
Syslog
| parse SyslogMessage with * "from " SrcIP " port" *
| where SrcIP in (
    _GetWatchlist('Test-Malicious-IP')
    | project SearchKey
)
```

### Detection Outcome

- Matches incoming log data against known malicious indicators
- Generates alerts for suspicious activity
- Supports threat hunting and investigation

---

# 📈 11. Security Operations Dashboard

A custom Microsoft Sentinel Workbook was created to provide centralized visibility into security events.

### Dashboard Components

- Failed Login Attempts
- Top Attacker IPs
- Threat Intelligence Matches
- Security Incidents
- Authentication Activity
- Geo-Location Analysis

📸 Screenshot:
![Workbook](screenshots/security_workbook.png)

---

# 🚨 12. ITIL-Aligned Incident Response Workflow

The incident response process follows the ITIL Incident Management lifecycle.

## Detection

Security incidents identified through:

- Microsoft Sentinel Alerts
- Analytics Rules
- Threat Intelligence Matches

---

## Logging

Events collected using:

- Azure Monitor
- Log Analytics Workspace
- Syslog

---

## Investigation

Activities performed:

- KQL Log Analysis
- Source IP Identification
- Threat Intelligence Correlation
- Authentication Review

Example:

```kusto
Syslog
| where SyslogMessage has_any ("Failed", "Invalid user")
```

---

## Response

Containment actions:

- Identified malicious source IP
- Blocked IP using Azure NSG
- Reviewed access controls
- Validated security configurations

---

## Recovery

- Confirmed service availability
- Verified monitoring coverage
- Reviewed security posture

---

## Lessons Learned

- Improved security visibility
- Enhanced threat detection capabilities
- Strengthened access controls
- Improved incident response readiness

---

## Incident Lifecycle

```text
Detection
    ↓
Logging
    ↓
Investigation
    ↓
Response
    ↓
Recovery
    ↓
Lessons Learned
```

---

# 🎯 Project Outcomes

This project demonstrates practical experience in:

- Azure Cloud Security
- Microsoft Sentinel
- SIEM Operations
- Threat Detection & Monitoring
- Threat Intelligence Integration
- Kusto Query Language (KQL)
- Identity & Access Management
- Network Security
- Incident Response
- MITRE ATT&CK Framework
- ITIL Incident Management

---

## 📌 Key Takeaway

This project evolved from a secure Azure deployment into a mini Security Operations Center (SOC) capable of:

✅ Secure Cloud Infrastructure

✅ Security Monitoring

✅ SIEM Integration

✅ Threat Intelligence Correlation

✅ MITRE ATT&CK Mapping

✅ Incident Detection & Investigation

✅ ITIL-Aligned Incident Response

✅ Security Analytics using KQL

This lab demonstrates the practical skills required for SOC Analyst, Cloud Security Engineer, Security Operations, and Cybersecurity roles.
