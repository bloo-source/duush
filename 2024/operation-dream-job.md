DARC Notes
# Operation Dream Job

## Navigating the Threat: Understanding Operation Dream Job

Operation Dream Job is a sophisticated cyberespionage campaign orchestrated by the Lazarus group, a North Korean threat actor known for its association with various high-profile attacks. This ongoing operation employs advanced tactics to compromise targets, primarily focusing on individuals working in software or decentralized finance (DeFi) platforms.

## Navigating the Threat: Understanding Operation Dream Job

Operation Dream Job is a sophisticated cyberespionage campaign orchestrated by the Lazarus group, a North Korean threat actor known for its association with various high-profile attacks. This ongoing operation employs advanced tactics to compromise targets, primarily focusing on individuals working in software or decentralized finance (DeFi) platforms.

## Attack methodology
The attack methodology used by this campaign can be outlined as follows:

| MITRE TACTICS      | STEPS INVOLVED                                                                                                                                                                       |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Initial Access     | - The operation begins with the threat actors posing as job recruiters on professional networking platforms, establishing initial connections with potential targets.        |
|                    |                                                                                                        |
| Execution          | - Malicious payloads, including C++ malware like "PlankWalk" and Linux backdoors such as "SimplexTea," are executed to establish a foothold within the corporate environment.   |
|                    |                                                                                                        |
| Persistence        | - Attackers establish persistence by modifying user profiles, employing reflective DLL injection, and manipulating system settings to ensure prolonged access.                   |
|                    |                                                                                                        |
| Privilege Escalation | - Vulnerability exploitation and techniques like reflective DLL injection allow threat actors to escalate privileges, gaining deeper access within the compromised environment. |
|                    |                                                                                                        |
| Defense Evasion    | - The deployed malware employs evasion techniques, such as masquerading as legitimate Windows binaries and using stealthy loaders like LidShift, to avoid detection.             |
|                    |                                                                                                        |
| Discovery          | - Extensive reconnaissance is performed to enumerate compromised systems, identify valuable targets, and understand the network's structure and defenses.                         |
|                    |                                                                                                        |
| Collection         | - Information-stealing trojans are used to collect sensitive data, including intellectual property and proprietary information, relevant to the attackers' objectives.           |
|                    |                                                                                                        |
| Exfiltration       | - Stolen data is exfiltrated from compromised systems to external servers controlled by the threat actors, potentially causing severe consequences for targeted organizations.    |

## Interim guidance

DARC team recommends the following guidance / best practices:
- **Email Security Measures**:
  - Enable Email Filtering: Implement advanced email filtering solutions to identify and block phishing emails, especially those containing job offers. Regularly update and configure filters to adapt to evolving threat patterns.
- **Web Proxy Restrictions**:
  - Restrict Access to Unnecessary Websites: Configure web proxies to restrict access to websites not relevant to business operations. Block access to job recruitment platforms known to be exploited by threat actors.
- **Endpoint Security Configurations**:
  - Application Whitelisting: Deploy application whitelisting to allow only authorized applications to run on endpoints. This helps prevent the execution of unauthorized C++ malware payloads like "PlankWalk."
- **Firewall Rules and IP Blocking**:
  - Update Firewall Rules: Regularly update firewall rules to block connections to known malicious IP addresses associated with Operation Dream Job. Implement IP blocking for suspicious traffic patterns.
- **DNS Filtering**:
  - Implement DNS Filtering: Use DNS filtering solutions to block access to malicious domains associated with the Lazarus group. This helps disrupt the command and control infrastructure.
- **Multi-Factor Authentication (MFA)**:
  - Enforce MFA Policies: Strengthen authentication by enforcing multi-factor authentication (MFA) for accessing critical systems. This mitigates the risk of unauthorized access, especially during the recruitment process.
- **Malware Detection Solutions**:
  - Deploy Advanced Malware Detection: Invest in advanced malware detection tools capable of identifying and blocking known Lazarus group malware such as "TOUCHMOVE," "SIDESHOW," and "TOUCHSHIFT."
- **PowerShell Security Configurations**:
  - Restrict PowerShell Usage: Limit the use of PowerShell for end-users and ensure that it is only used for legitimate purposes. Monitor and restrict PowerShell script execution to prevent the deployment of "CloudBurst" malware.
- **Web Security Best Practices**:
  - Update and Patch Web Applications: Regularly update and patch web applications, especially content management systems like WordPress. Address vulnerabilities to mitigate the risk of remote template injections.
- **Registry Access Control**:
  - Enhance Registry Access Controls: Strengthen access controls for the Windows Registry to prevent unauthorized modifications. Regularly review and monitor changes to the registry, focusing on persistence mechanisms.
- **Network Intrusion Prevention**:
  - Implement Network Intrusion Prevention: Deploy network intrusion prevention systems (NIPS) to detect and block malicious activities associated with Operation Dream Job. Customize NIPS rules to match threat signatures.
- **User Privilege Management**:
  - Regularly Review User Privileges: Conduct regular reviews of user privileges and enforce the principle of least privilege. Limit user access to critical systems to prevent unauthorized changes.

## DARC Managed Threat Hunting Queries

To detect the activities associated with the context of Operation Dream Job, we can create several DQL queries targeting different aspects of the network and system security. Here are some DQL queries that align with the security measures mentioned:

1. Detecting phishing emails with job offers:
```
stream=email-gateway where subject like '%job offer%' or subject like '%career opportunity%' | select subject, sender, recipient
```

2. Restricting access to unnecessary websites:
```
stream=web-filter where action='ALLOWED' and category='Job Recruitment' | select user, domain
```

3. Detecting "PlankWalk" launchers:
```
stream=ep-process where (image like '%destextapi.dll' or
                     	image like '%manextapi.dll' or
                     	image like '%pathextapi.dll' or
                     	image like '%preextapi.dll' or
                     	image like '%Wbemcomn.dll') and
                     	commandline like '*Vault\\cache*.db'
```

4. Blocking connections to known malicious IP addresses:
```
stream=firewall where action='PACKET_ALLOWED' and dstip in ['malicious_ip1', 'malicious_ip2'] | select srcip, dstip, action
```

*Note: For placeholders namely, ['malicious_ip1',malicious_ip2'] to work, kindly ensure you have a Threat Intelligence feeds integrated within your DNIF deployment.*

5. Blocking access to malicious domains:
```
stream=dns where querytype='A' and answer in ['malicious_domain1', 'malicious_domain2'] | select query, answer
```

*Note: For placeholders namely, ['malicious_domain1',malicious_domain2'] to work, kindly ensure you have a Threat Intelligence feeds integrated within your DNIF deployment.*

6. Ensuring MFA is enforced (assuming MFA events are logged):
```
stream=authentication where action='LOGIN' and authproto!='MFA' | select user, srcip, status
```

7. Identifying known Lazarus group malware:
```
stream=threat where threat in ['TOUCHMOVE', 'SIDESHOW', 'TOUCHSHIFT'] | select user, dstip, file, threat
```

8. Monitoring PowerShell script execution:
```
stream=ep-process where eid = '4104' and action='PROCESS_ADDED' | select user, commandline, image
```

9. Reviewing user privileges:
```
stream=iam where action='PRIVILEGE_CHANGED' | select user, role, status
```

These queries are only indicative in nature with an assumption that the DNIF platform is configured to capture and log the relevant data that corresponds to the security measures mentioned. Adjustments may be needed based on the actual data fields and log formats used in the organization's DNIF deployment.

## Conclusion

Operation Dream Job represents a significant escalation in the Lazarus group's cyber capabilities, targeting individuals across major operating systems and industries. Organizations must remain vigilant, enhance their cybersecurity posture, and collaborate on threat intelligence sharing to effectively counter this evolving threat landscape. By understanding the attack methodology and implementing robust security measures, businesses and individuals can mitigate the risks associated with Operation Dream Job.

## References

1. ![Stealing the LIGHTSHOW (Part One) — North Korea's UNC2970](https://www.mandiant.com/resources/blog/lightshow-north-korea-unc2970)
2. ![Security researchers targeted with new malware via job offers on LinkedIn](https://www.bleepingcomputer.com/news/security/security-researchers-targeted-with-new-malware-via-job-offers-on-linkedin/#google_vignette)


