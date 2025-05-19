# Threat Hunt Report: Suspicious Use of Certutil to Base64 Encode a Payload
- [Scenario Creation](https://github.com/huyrocks123/threat-hunting-scenario-suspicious-use-of-certutil-to-base64-encode-a-payload/blob/main/threat-hunting-scenario-suspicious-use-of-certutil-to-base64-encode-a-payload-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Windows built-in tool: certutil.exe

##  Scenario

Security monitoring flagged suspicious file activity from a system belonging to a user named "huy." This activity involves the use of the certutil.exe utility — a legitimate Windows binary that can be abused by threat actors to encode/decode payloads as part of living-off-the-land (LOLBins) techniques. The suspected behavior includes base64 encoding a suspicious file named payload.txt using certutil and saving the output to a file named encoded.txt.

The objective of this threat hunt is to detect the use of certutil.exe for payload encoding and investigate associated file and process activities. Any unauthorized or malicious use must be flagged and appropriate remediation actions taken.

### High-Level TOR-Related IoC Discovery Plan

- **Check DeviceProcessEvents** for suspicious use of certutil.exe, especially with flags like -encode, -decode, or usage pointing to uncommon or suspicious file names.
- **Check DeviceFileEvents** for encoded output file.

---

## Steps Taken

### 1. Searched the DeviceProcessEvents Table for Suspicious Certutil Encoding Activity

Searched for any use of certutil.exe with the -encode flag. User, huy, executed the command, "certutil.exe -encode C:\Users\Public\sample.exe C:\Users\Public\payload.txt" to Base64-encode a file at 2025-05-19T20:00:21.5641348Z.

**Query used to locate events:**

DeviceProcessEvents
| where DeviceName == "huy"
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has "-encode"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath

<img width="1032" alt="Screenshot 2025-05-19 at 4 41 54 PM" src="https://github.com/user-attachments/assets/9fce2489-af67-4f2d-9f82-6cc9fdbb0363" />

---

### 2. Searched the DeviceFileEvents Table for File Deletion of the Original Executable

Searched for file events involving sample.exe. This revealed that shortly after the Base64-encoded file was created, the original sample.exe file was deleted at 2025-05-19T20:00:34.3203707Z by user, huy. This behavior suggests an attempt to cover tracks after encoding the payload.

**Query used to locate event:**

DeviceFileEvents
| where FileName == "sample.exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ActionType

<img width="987" alt="Screenshot 2025-05-19 at 4 43 31 PM" src="https://github.com/user-attachments/assets/64bcb02e-d057-49e8-890c-7b863f22df2e" />

---

## Chronological Event Timeline 

### 1. Certutil.exe was executed by user huy to encode sample.exe into Base64 format, outputting payload.txt.

- **Timestamp:** 2025-05-19T20:00:21.5641348Z
- **Event:** The user huy executed certutil.exe to Base64-encode a file named sample.exe, outputting the result to payload.txt.
- **Action:** Suspicious encoding operation detected using a Living-off-the-Land Binary (LOLBIN).
- **Command** certutil.exe -encode C:\Users\Public\sample.exe C:\Users\Public\payload.txt

### 2. The original executable file sample.exe was deleted by the same user shortly after encoding.

- **Timestamp:** 2025-05-19T20:00:34.3203707Z
- **Event:** The original executable file sample.exe was deleted by the same user shortly after encoding.
- **Action:** File deletion detected, potentially to evade detection and cover tracks.
- **File Path:** C:\Users\Public\sample.exe

---

## Summary

A threat hunt was initiated following suspicious behavior involving the native Windows binary certutil.exe. This tool is commonly abused by threat actors as part of Living-off-the-Land (LOLBins) techniques to avoid detection.

During the investigation:

The user huy executed certutil.exe with the -encode flag to Base64-encode a file named sample.exe.

The output of the encoding was saved as payload.txt.

Shortly after the encoding activity, the original file sample.exe was deleted—behavior often associated with attempts to evade forensic analysis or hinder incident response.

This pattern of activity strongly suggests intentional obfuscation or preparation for exfiltration, warranting further investigation into the context and origin of sample.exe.

---

## Response Taken

Raised an alert and escalated to the SOC (Security Operations Center) team for in-depth analysis of user huy's activities.

Conducted a search for the presence of payload.txt and any outbound network connections from the device to determine if data exfiltration occurred.

Quarantined the endpoint for forensic review and containment.

Initiated a review of other endpoints for similar use of certutil.exe and sample.exe to rule out lateral movement.

Implemented a detection rule in Microsoft Defender for Endpoint to flag future instances of certutil.exe being used with the -encode flag.

---
