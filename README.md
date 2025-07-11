# Threat Hunt: Data Exfiltration by a Disgruntled Employee

### 1. Project Scenario & Objective

This [project simulates](https://github.com/jorjuarez/Cybersecurity-Portfolio-Public/tree/main/Threat%20Hunt%3A%20Data%20Exfiltration%20by%20a%20Disgruntled%20Employee#project-appendix-simulating-data-exfiltration) a threat hunt for a potential insider threat.

* **Scenario:** A high-risk employee, "John Doe" (account: `analyst1`), was recently put on a performance improvement plan (PIP). Management raised concerns that this employee might try to steal proprietary data from their corporate device (`arguswinten`) before resigning.
* **Objective:** Proactively hunt for and investigate `analyst1`'s on-device activities to determine if any data collection or exfiltration is taking place, and respond accordingly using the NIST 800-61 framework.
* **Hypothesis:** The employee will likely try to compress sensitive information and exfiltrate it to a personal cloud storage location using common system utilities to blend in with normal activity.

---
### 2. Investigation & Findings

The investigation focused on analyzing logs from Microsoft Defender for Endpoint, specifically looking for file creation and network connection events originating from the target user and device.

#### Finding 1: Suspicious Script Creation
At **1:58:33 PM on May 8, 2025**, the user `analyst1` created a PowerShell script named `exfiltratedata.ps1` in the `C:\ProgramData` directory. This location is unusual for user-generated scripts and immediately raised suspicion.

**Supporting Query:**
```kql
// Query to show creation of exfiltratedata.ps1 by analyst1
DeviceFileEvents
| where DeviceName == "arguswinten" and InitiatingProcessAccountName == "analyst1"
| where Timestamp between (datetime(2025-05-08T00:00:00Z) .. datetime(2025-05-08T23:59:59Z))
| where FileName == "exfiltratedata.ps1" and ActionType == "FileCreated"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc

```

<img width="910" height="472" alt="image" src="https://github.com/user-attachments/assets/1be9f92d-2261-403c-bdfc-264ca23c6fd2" />


#### Finding 2: Data Archiving
Seconds later, at **1:58:41 PM**, a ZIP archive named `employee-data-20250508185834.zip` was created on the system. The process that created this file was `7z.exe`, indicating that an archiving utility was used to compress data, which directly supports our hypothesis.

```kql
// Query to show creation of the specific ZIP file by the script's activity
DeviceFileEvents
| where DeviceName == "arguswinten" and InitiatingProcessAccountName == "analyst1" 
| where Timestamp between (datetime(2025-05-08T00:00:00Z) .. datetime(2025-05-08T23:59:59Z))
| where FileName == "employee-data-20250508185834.zip" and ActionType == "FileCreated" and InitiatingProcessFileName == "7z.exe"
| project Timestamp, ActionType, FileName, FolderPath, FileSize, InitiatingProcessAccountName, InitiatingProcessFileName
| sort by Timestamp asc

```
<img width="1024" height="448" alt="image" src="https://github.com/user-attachments/assets/da5632a3-c5ff-46d0-8045-b19a16afda3a" />




#### Finding 3: Data Exfiltration to Cloud Storage
Immediately following the file archiving, at **1:58:41 PM**, the `exfiltratedata.ps1` script initiated a successful network connection to an external Azure Blob Storage domain: `https://sacyberrangedanger.blob.core.windows.net`. This action confirms that data was exfiltrated from the corporate device to an unauthorized external location, proving the most critical part of the hypothesis.

```kql
// Query to show the network connection to the exfiltration domain
DeviceNetworkEvents
| where DeviceName == "arguswinten" and InitiatingProcessAccountName == "analyst1"
| where Timestamp between (datetime(2025-05-08T00:00:00Z) .. datetime(2025-05-08T23:59:59Z))
| where InitiatingProcessFileName =~ "powershell.exe" and InitiatingProcessCommandLine contains "exfiltratedata.ps1"
| where RemoteUrl contains "sacyberrangedanger.blob.core.windows.net"
| project Timestamp, ActionType, LocalIP, RemoteUrl, RemoteIP, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc

```

<img width="1277" height="478" alt="image" src="https://github.com/user-attachments/assets/bcba1dc3-7299-463c-8bb3-2911d297e851" />


---

### 3. Incident Response

Upon discovering the active data exfiltration, the following response actions were taken:
* **Containment:** The device (`arguswinten`) was **immediately isolated** from the network using Microsoft Defender for Endpoint to sever the connection and prevent any further data transfer.
* **Communication:** The employee's manager was immediately notified of the findings, including the evidence of the script creating and exfiltrating archives at regular intervals.
* **Analysis:** It was confirmed that the script used hardcoded credentials to access the external storage account and was designed to run as a privileged system process.

---

### 4. MITRE ATT&CK® Framework Mapping

The observed activities map to several tactics and techniques within the ATT&CK framework:

| Tactic | Technique ID | Description in this Hunt |
| :--- | :--- | :--- |
| **Execution** | T1059.001 | The attack was initiated via a **PowerShell** script. |
| **Collection** | T1560.001 | Data was staged for exfiltration by archiving it with the **7-Zip utility**. |
| **Credential Access** | T1552.001 | The script used **hardcoded credentials** (an Azure Storage key) to access the external storage. |
| **Exfiltration** | T1567.002 | Data was exfiltrated over a web service to **cloud storage** (Azure Blob Storage). |

---

### 5. Strategic Improvements & Recommendations

This incident highlighted opportunities to harden the environment against insider threats:

* **Endpoint Security:** Implement stricter application control policies using **Windows Defender Application Control (WDAC) or AppLocker** to prevent the execution of unauthorized scripts and utilities like `7z.exe`.
* **Detection Engineering:** Create new **MDE/Sentinel alerts** to detect suspicious PowerShell behaviors, such as the use of `-ExecutionPolicy Bypass`, script creation in unusual directories like `C:\ProgramData`, or a high frequency of file compression activities by a single user.
