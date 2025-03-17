# Azure-Honeynet-with-SOC-Results


## Attack Maps Before Hardening / Security Controls

<img src="https://i.imgur.com/4RPbGMs.png" width="500">

<img src="https://i.imgur.com/D9c4Od3.jpeg" width="500">



## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:

|Start Time: 2025-03-15 22:06:32
|Stop Time: 2025-03-16 22:06:32

| Metric                                        | Count        |
|-----------------------------------------------|----------------------------|
| SecurityEvent         | 133475|
| Syslog | 10964|
|SecurityAlert       | 136 |
| SecurityIncident     | 188 |
| AzureNetworkAnalytics_CL                  | 13172 |

## Attack Maps After Hardening / Security Controls

<img src="https://i.imgur.com/aZpGIV4.png" width="250">

All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.

## Metrics After Hardening/Security Controls 

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:

|Start Time: 2025-03-16 23:11:23
|Stop Time: 2025-03-17 23:11:23

| Metric                                        | Count        |
|-----------------------------------------------|----------------------------|
| SecurityEvent         | 16712|
| Syslog | 21|
|SecurityAlert       | 0 |
| SecurityIncident     | 0 |
| AzureNetworkAnalytics_CL                  | 0 |


* SecurityEvent: ↓ 87.48%
* Syslog: ↓ 99.81%
* SecurityAlert: ↓ 100%
* SecurityIncident: ↓ 100%
* AzureNetworkAnalytics_CL: ↓ 100%

  
## KQL Queries

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Start/Stop Time                              | range x from 1 to 1 step 1<br>\| project StartTime = ago(24h), StopTime = now()                                                                  |
| Security Events (Windows VMs)                | SecurityEvent<br>\| where TimeGenerated>= ago(24h)<br>\| count                                                                                   |
| Syslog (Linux VMs)                           | Syslog<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                                         |
| SecurityAlert (Microsoft Defender for Cloud) | Security Alert<br>\| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"<br>\| where TimeGenerated >= ago(24h)<br>\| count |
| Security Incident (Sentinel Incidents)       | SecurityIncident<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                               |
| NSG Inbound Malicious Flows Allowed          | AzureNetworkAnalytics_CL<br>\| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0<br>\| where TimeGenerated >= ago(24h)<br>\| count    |
