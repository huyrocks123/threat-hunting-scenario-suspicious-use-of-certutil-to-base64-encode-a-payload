# Threat Event (Suspicious Use of Certutil to Base64 Encode a Payload)
**Attacker uses certutil.exe to encode a suspicious executable into Base64 format, possibly to evade detection or exfiltrate data.**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Places a benign or suspicious .exe file in C:\Users\Public\, named sample.exe:
Copy-Item "C:\Windows\System32\notepad.exe" "C:\Users\Public\sample.exe"
2. Encodes the file using certutil:
certutil -encode "C:\Users\Public\sample.exe" "C:\Users\Public\payload.txt"
3. Deletes the original .exe:
del "C:\Users\Public\sample.exe"

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|	https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose**| 	Detects use of certutil.exe to encode or decode files. |


| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|	https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose**| 	Detects creation of payload.txt and deletion of original sample.exe. |

---

## Related Queries:
```kql
// Detect suspicious certutil encoding activity
DeviceProcessEvents
| where FileName == "certutil.exe"
| where ProcessCommandLine contains "-encode"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect the creation of encoded payload file
DeviceFileEvents
| where FileName == "payload.txt"
| where FolderPath == "C:\\Users\\Public"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

// Detect deletion of original executable
DeviceFileEvents
| where FileName == "sample.exe"
| where ActionType == "FileDeleted"
| where FolderPath == "C:\\Users\\Public"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
```

---

## Created By:
- **Author Name**: Huy Tang
- **Author Contact**: https://www.linkedin.com/in/huy-t-892a51317/
- **Date**: May 19, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | May 19, 2025  | Huy Tang  
