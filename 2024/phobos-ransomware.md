# DARC Notes: Phobos Ransomware

## Navigating the Threat: Understanding Phobos Ransomware

Phobos Ransomware operates on a ransomware-as-a-service (RaaS) model, and its impact has been notably felt across state, local, tribal, and territorial (SLTT) governments. Municipalities, emergency services, educational institutions, and critical infrastructure entities have fallen victim to Phobos, resulting in substantial ransom payouts.

## Attack Methodology

The attack methodology used by Phobos ransomware can be outlined as follows:

### MITRE TACTICS

| MITRE TACTICS               | STEPS INVOLVED                                                                                                                                                                                                                       |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Reconnaissance and Initial Access | - Phobos gains access through phishing campaigns, exploiting vulnerable RDP ports, and leveraging RDP on Windows environments. - Initial access is often achieved through open source brute force tools.                      |
| Execution and Privilege Escalation | - Executes commands like 1saas.exe or cmd.exe to deploy elevated Phobos payloads. - Utilizes Windows command shell for control with different permission levels. - Deploys Smokeloader for payload decryption.       |
| Defense Evasion Capabilities | - Modifies system firewall configurations using commands like netsh firewall set opmode mode=disable. - Uses tools like Universal Virus Sniffer, Process Hacker, and PowerTool for detection evasion.                             |
| Persistence and Privilege Escalation | - Utilizes commands like Exec.exe or bcdedit.exe for persistence. - Uses Windows Startup folders and Run Registry Keys for maintaining persistence. - Exploits built-in Windows API functions for privilege escalation. |
| Discovery and Credential Access | - Employs open source tools like Bloodhound and Sharphound for active directory enumeration. - Uses Mimikatz and NirSoft for exporting browser client credentials. - Enumerates connected storage devices, running processes, and encrypts user files. |
| Exfiltration                | - Utilizes WinSCP and Mega.io for file exfiltration. - Connects directly to FTP servers and exports victim files to a cloud storage provider. - Archives data as .rar or .zip files for exfiltration.                            |


### Interim Guidance

The DARC team recommends following the guidance from the CISA in their latest CSA. This includes the following:
- Strictly limit the use of RDP and other remote desktop services.
- Apply phishing-resistant multifactor authentication (MFA).
- Segment networks to prevent the spread of ransomware.
- Install, regularly update, and enable real-time detection for antivirus software on all hosts.

### DARC Managed Threat Hunting Queries

- **Disable User Account Control (UAC)**
- **Invoking Accessible Feature (Sticky Keys Backdoor Setup)**
- **RDP and Disabling Network-Level Authentication**
- **Service Configuration Changes**
- **File Sharing File Service**

These queries are designed to detect changes to registry keys that are indicative of the activities commonly associated with Phobos ransomware. Please ensure that the field names and stream names match the actual data in your DNIF environment.

## Conclusion

The intricate workings of Phobos ransomware and its variant outlined in this brief emphasize the importance of vigilance and strategic defense measures. The DARC team recommends thorough implementation of CISA's mitigation strategies, including stringent RDP controls, multifactor authentication, network segmentation, and continuous monitoring.
For comprehensive guidance and detailed mitigation strategies, refer to the CISA advisory. The DARC team emphasizes the importance of not only understanding the threat but actively incorporating recommended defenses into cybersecurity practices.

## References

- [#StopRansomware: Phobos Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060a)
- [A deep dive into Phobos ransomware](https://www.malwarebytes.com/blog/news/2019/07/a-deep-dive-into-phobos-ransomware)
