# Cloud-Native Threat Modeling (STRIDE)

This document outlines the threat modeling scenarios used to design the detection rules for this Detection-as-Code pipeline. By applying the STRIDE methodology to cloud environments, we ensure our SIEM rules are directly mapped to realistic adversary behaviors.

---

## Scenario 1: AWS Console Login Without MFA
* **STRIDE Category:** Spoofing
* **MITRE ATT&CK Mapping:** T1078.004 (Valid Accounts: Cloud Accounts)
* **Threat Description:** An adversary acquires compromised IAM user credentials (e.g., via phishing or credential stuffing) and successfully logs into the AWS Management Console. 
* **Impact:** The attacker masquerades as a legitimate user. Because Multi-Factor Authentication (MFA) is disabled, the system cannot verify the user's true identity, granting the attacker initial access to the cloud environment.
* **Detection Strategy:** Monitor AWS CloudTrail logs for `ConsoleLogin` events where the `MFAUsed` field evaluates to `false`.

---

## Scenario 2: Cloud Metadata API Extraction (EC2 SSRF)
* **STRIDE Category:** Information Disclosure
* **MITRE ATT&CK Mapping:** T1552.005 (Credentials from Password Stores: Cloud Instance Metadata API)
* **Threat Description:** An attacker exploits a Server-Side Request Forgery (SSRF) vulnerability on an external-facing web application hosted on an AWS EC2 instance. They force the application to query the internal AWS metadata IP address (`169.254.169.254`).
* **Impact:** The attacker extracts temporary IAM security credentials assigned to the EC2 instance, allowing them to authenticate to the AWS API from outside the network.
* **Detection Strategy:** Monitor network traffic or proxy logs for unexpected outbound requests to `169.254.169.254` originating from web application processes.

---

## Scenario 3: Malicious OAuth App Consent (M365)
* **STRIDE Category:** Elevation of Privilege
* **MITRE ATT&CK Mapping:** T1528 (Steal Application Access Token)
* **Threat Description:** A user is subjected to an illicit consent phishing attack. They are tricked into granting a malicious third-party Azure AD/M365 application sweeping permissions (e.g., `Mail.ReadWrite`).
* **Impact:** The attacker bypasses traditional authentication entirely. The malicious application is elevated to interact with the user's data on their behalf, allowing the attacker to read emails or exfiltrate data indefinitely.
* **Detection Strategy:** Monitor Azure AD audit logs for the `Add app role assignment to service principal` operation, specifically looking for high-risk permissions granted to unknown or unverified applications.