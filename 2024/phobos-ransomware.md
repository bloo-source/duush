DARC Notes
# Phobos Ransomware

## Navigating the Threat: Understanding Phobos Ransomware

Phobos Ransomware operates on a ransomware-as-a-service (RaaS) model, and its impact has been notably felt across state, local, tribal, and territorial (SLTT) governments. Municipalities, emergency services, educational institutions, and critical infrastructure entities have fallen victim to Phobos, resulting in substantial ransom payouts.

### Attack methodology

The attack methodology used by Phobos ransomware can be outlined as follows:

| MITRE TACTICS            | STEPS INVOLVED                                                                                                                                      |
|--------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| Reconnaissance and Initial Access | - Phobos gains access through phishing campaigns, exploiting vulnerable RDP ports, and leveraging RDP on Windows environments. - Initial access is often achieved through open source brute force tools.   |
| Execution and Privilege Escalation | - Executes commands like 1saas.exe or cmd.exe to deploy elevated Phobos payloads.
- Utilizes Windows command shell for control with different permission levels.                                           
- Deploys Smokeloader for payload decryption.
| Smokeloader Deployment:    | - Smokeloader operates in three phases, manipulating API functions, obfuscating C2 activity, and deploying destructive malware.
- Uses VirtualAlloc or VirtualProtect API functions for evasion.
| Defense Evasion Capabilities | - Modifies system firewall configurations using commands like netsh firewall set opmode mode=disable.
- Uses tools like Universal Virus Sniffer, Process Hacker, and PowerTool for detection evasion.                                                     
| Persistence and Privilege Escalation | - Utilizes commands like Exec.exe or bcdedit[.]exe for persistence.             - Uses Windows Startup folders and Run Registry Keys for maintaining persistence.                                        - Exploits built-in Windows API functions for privilege escalation.                                                     
| Discovery and Credential Access | - Employs open source tools like Bloodhound and Sharphound for active directory enumeration.                                                        
- Uses Mimikatz and NirSoft for exporting browser client credentials.                                                    - Enumerates connected storage devices, running processes, and encrypts user files.                                                                  
| Exfiltration               | - Utilizes WinSCP and ![Mega.io](http://Mega.io) for file exfiltration.                   - Connects directly to FTP servers and exports victim files to a cloud storage provider.                                 - Archives data as .rar or .zip files for exfiltration.                                                                                              
| Impact                     | - Deletes volume shadow copies to prevent file recovery.                                                                                              |
- Encrypts all connected logical drives on the target host.                                                              - Extorts victims via email or voice calls, using onion sites to list victims and host stolen data.                       - Communicates through various instant messaging applications.                                                           |                            |

### Interim guidance

DARC team recommends following the guidance from the CISA in their latest CSA. This includes the following:

- **Strictly limit the use of RDP and other remote desktop services. If RDP is necessary, rigorously apply best practices, for example**:
  - Audit the network for systems using RDP.
  - Close unused RDP ports.
  - Enforce account lockouts after a specified number of attempts.
  - ![Apply phishing-resistant multifactor authentication (MFA)](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf)
  - Log RDP login attempts.
- **Disable command-line and scripting activities and permissions**
- **Review domain controllers, servers, workstations, and active directories for new and/or unrecognized accounts**
- **Require phishing-resistant multifactor authentication (MFA)** for all services to the extent possible, particularly for webmail, virtual private networks (VPNs), and accounts that access critical systems.
- **Segment networks** to prevent the spread of ransomware.
- **Identify, detect, and investigate abnormal activity and potential traversal of the indicated ransomware with a networking monitoring tool**.
- **Install, regularly update, and enable real time detection for antivirus software** on all hosts.
- **Disable unused ports and protocols**
- **Ensure all backup data is encrypted, immutable**

## DARC Managed Threat Hunting Queries

1. Disable User Account Control (UAC):
```
stream=win-audit where action='POLICY_CHANGED' and object='%CurrentVersion\Policies\System%EnableLUA%0' | select User, SrcIP, System
```

2. Invoking accessible feature (Sticky Keys backdoor setup):
```
stream=win-audit where action='POLICY_CHANGED' and (object='%Image File Execution Options%' and object='%sethc.exe%Magnify.exe%HelpPane.exe%utilman.exe') | select User, SrcIP, System
```

3. RDP and disabling network-level authentication:
```
stream=win-audit where action='POLICY_CHANGED' and (object='%Terminal Services%Terminal Server%RDP-Tcp') | select User, SrcIP, System
```

4. Service Configuration Changes
```
stream=configuration where action='CONFIGURATION_CHANGED' and logevent like '%sc config%' and (logevent like '%start= autonet%' or logevent like '%start= disabled%')
```

*Note: Look for batch modifications to service configurations that may indicate an attempt to weaken system defenses. Look for Event IDs - 7040 (A service's start type has been changed (can indicate changes made by 'sc config')*

5. File Sharing File Service
```
stream=configuration where action='CONFIGURATION_CHANGED' and logevent like '%dism /online /enable-feature%' and config like '%File-Services%' and config like '%/NoRestart%'
```

*Note: Detect command-line arguments that enable file services without restarting the system, which could be used to maintain persistence or enable lateral movement. Check for similar commands within Event ID 4104 if you have script block logging enabled. Look for the enabling of file services that are not commonly used or required for a given system's role.*

These queries are designed to detect changes to registry keys that are indicative of the activities commonly associated with Phobos ransomware. Please ensure that the field names and stream names match the actual data in your DNIF environment.

## Conclusion

The intricate workings of Phobos ransomware and its variant outlined in this brief emphasize the importance of vigilance and strategic defense measures. The DARC team recommends thorough implementation of CISA's mitigation strategies, including stringent RDP controls, multifactor authentication, network segmentation, and continuous monitoring.
For comprehensive guidance and detailed mitigation strategies, refer to the CISA advisory. The DARC team emphasizes the importance of not only understanding the threat but actively incorporating recommended defenses into cybersecurity practices.

## References

1. ![#StopRansomware: Phobos Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060a)
2. ![A deep dive into Phobos ransomware](https://www.malwarebytes.com/blog/news/2019/07/a-deep-dive-into-phobos-ransomware)
