# AWS IAM Security Audit Tool

This Python-based tool performs a security audit of IAM users in your AWS account. It generates an Excel report detailing users, policies, access keys, MFA status, and potential privilege escalation risks.

---

## 📦 Files Included

- `iam_audit.py` – Main audit script
- `requirements.txt` – Python dependencies
- `README.md` – Setup and usage instructions

---

## 🛠 Requirements

- Python 3.6+
- AWS account with IAM `List/Get` permissions
- AWS credentials (via CLI or env vars)

---

## 🔐 Setting AWS Credentials

You **must set credentials** before running the script.

### For Windows, please download and install aws cli from this link:
https://awscli.amazonaws.com/AWSCLIV2.msi

### For MAC, please download and install aws cli from this link:
https://awscli.amazonaws.com/AWSCLIV2.pkg

### For Linux, please run this command to install aws cli:
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

### Use AWS CLI to set credentials
aws configure

📥 Installation
Install required dependencies:


pip install -r requirements.txt
▶️ Usage
Run the script:


python iam_audit.py
This will generate:


aws_iam_security_audit.xlsx
📊 Output Columns
UserName

Created

AttachedPolicies

InlinePolicies

AccessKeys

MFAEnabled

PrivilegeEscalationRisk

🔒 What It Checks
IAM users & metadata

Attached and inline policies

Access key status and age

MFA configuration

Privilege escalation indicators (based on known IAM abuse techniques)

🧠 Reference
Based on research from Rhino Security Labs
