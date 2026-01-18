# Awesome Cloud Security

> A curated collection of 100+ cloud security tools, frameworks, and resources for securing AWS, Azure, GCP, and Kubernetes environments.

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![GitHub stars](https://img.shields.io/github/stars/Su1ph3r/awesome-cloud-security?style=social)](https://github.com/Su1ph3r/awesome-cloud-security/stargazers)
[![GitHub last commit](https://img.shields.io/github/last-commit/Su1ph3r/awesome-cloud-security)](https://github.com/Su1ph3r/awesome-cloud-security/commits/main)

Whether you're a **penetration tester**, **cloud security engineer**, **DevSecOps professional**, or **security researcher**, this list provides essential tools for:

- **Offensive Security** - Cloud penetration testing, red team operations, and attack simulation
- **Defensive Security** - CSPM, vulnerability scanning, and security monitoring
- **Compliance & Governance** - CIS benchmarks, policy enforcement, and audit tools
- **IAM Security** - Privilege escalation detection, policy analysis, and access reviews

---

## Why This List?

Cloud environments are complex. With shared responsibility models, ephemeral resources, and multi-cloud architectures, security teams need specialized tools. This list focuses exclusively on **actively maintained, practical tools** that security professionals actually use.

**Star this repo** to keep it in your toolkit and get updates when new tools are added.

---

## Contents

- [Multi-Cloud Tools](#multi-cloud-tools)
  - [Security Posture Management (CSPM)](#security-posture-management-cspm)
  - [Infrastructure as Code (IaC) Security](#infrastructure-as-code-iac-security)
  - [Asset Inventory & Discovery](#asset-inventory--discovery)
- [Attack Path Analysis](#attack-path-analysis)
- [AWS Security Tools](#aws-security-tools)
  - [Offensive](#aws-offensive)
  - [Defensive](#aws-defensive)
  - [IAM Analysis](#aws-iam-analysis)
  - [S3 Security](#s3-security)
  - [Native AWS Services](#native-aws-services)
- [Azure Security Tools](#azure-security-tools)
  - [Offensive](#azure-offensive)
  - [Defensive](#azure-defensive)
  - [IAM/Entra ID Analysis](#iamentra-id-analysis)
  - [Native Azure Services](#native-azure-services)
- [GCP Security Tools](#gcp-security-tools)
  - [Offensive](#gcp-offensive)
  - [Defensive](#gcp-defensive)
  - [Native GCP Services](#native-gcp-services)
- [Container & Kubernetes Security](#container--kubernetes-security)
  - [Image Scanning](#image-scanning)
  - [Runtime Security](#runtime-security)
  - [Kubernetes Audit & Compliance](#kubernetes-audit--compliance)
- [IAM Analysis](#iam-analysis)
- [Secrets Scanning](#secrets-scanning)
- [Compliance & Governance](#compliance--governance)
- [Serverless Security](#serverless-security)
- [Training Labs & Vulnerable Environments](#training-labs--vulnerable-environments)
- [Contributing](#contributing)

---

## Multi-Cloud Tools

### Security Posture Management (CSPM)

- [Nubicustos](https://github.com/Su1ph3r/Nubicustos) - Unified security platform orchestrating 24+ tools with attack path analysis and compliance across AWS, Azure, GCP, and Kubernetes.
- [Prowler](https://github.com/prowler-cloud/prowler) - Security assessment tool for AWS, Azure, GCP, and Kubernetes with CIS benchmark checks.
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing tool supporting AWS, Azure, GCP, Alibaba Cloud, and Oracle Cloud.
- [CloudSploit](https://github.com/aquasecurity/cloudsploit) - Cloud security configuration scanner for AWS, Azure, GCP, and Oracle Cloud.
- [CloudQuery](https://github.com/cloudquery/cloudquery) - Open source cloud asset inventory with SQL-based policy engine.
- [Steampipe](https://github.com/turbot/steampipe) - Query cloud APIs using SQL with pre-built compliance mods.
- [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian) - Rules engine for cloud security, cost optimization, and governance.
- [Magpie](https://github.com/openraven/magpie) - Cloud security posture management with data discovery.

### Infrastructure as Code (IaC) Security

- [Checkov](https://github.com/bridgecrewio/checkov) - Static analysis for Terraform, CloudFormation, Kubernetes, Helm, and ARM templates.
- [tfsec](https://github.com/aquasecurity/tfsec) - Security scanner for Terraform code.
- [Terrascan](https://github.com/tenable/terrascan) - Static code analyzer for IaC with 500+ policies.
- [KICS](https://github.com/Checkmarx/kics) - Infrastructure as Code scanner for security vulnerabilities.
- [Regula](https://github.com/fugue/regula) - Policy engine for Terraform and CloudFormation using Rego.
- [Snyk IaC](https://github.com/snyk/cli) - IaC security scanning as part of the Snyk platform.
- [Trivy](https://github.com/aquasecurity/trivy) - Comprehensive scanner including IaC misconfigurations.

### Asset Inventory & Discovery

- [Cartography](https://github.com/lyft/cartography) - Graph-based asset inventory and relationship mapping.
- [cloudlist](https://github.com/projectdiscovery/cloudlist) - Multi-cloud asset listing tool.
- [Resoto](https://github.com/someengineering/resoto) - Infrastructure inventory with search and analytics.

---

## Attack Path Analysis

- [Nubicustos](https://github.com/Su1ph3r/Nubicustos) - Graph-based attack chain discovery with MITRE ATT&CK mapping and exploitability scoring.
- [CloudFox](https://github.com/BishopFox/cloudfox) - AWS attack surface enumeration for penetration testers.
- [Cartography](https://github.com/lyft/cartography) - Neo4j-based asset relationship mapping for attack path analysis.
- [PMapper](https://github.com/nccgroup/PMapper) - AWS IAM privilege escalation path finder using graph analysis.
- [Cloudmapper](https://github.com/duo-labs/cloudmapper) - AWS environment visualization and analysis.
- [AzureHound](https://github.com/BloodHoundAD/AzureHound) - Azure data collector for BloodHound attack path analysis.

---

## AWS Security Tools

### AWS Offensive

- [Pacu](https://github.com/RhinoSecurityLabs/pacu) - AWS exploitation framework for penetration testing.
- [aws_pwn](https://github.com/dagrz/aws_pwn) - Collection of AWS penetration testing tools.
- [CloudFox](https://github.com/BishopFox/cloudfox) - Attack surface enumeration for AWS.
- [Endgame](https://github.com/salesforce/endgame) - AWS resource policy exploitation tool for privilege escalation.
- [Weirdaal](https://github.com/carnal0wnage/weirdAAL) - AWS attack library.
- [ccat](https://github.com/RhinoSecurityLabs/ccat) - Cloud Container Attack Tool.
- [Nimbostratus](https://github.com/andresriancho/nimbostratus) - AWS security assessment tool.

### AWS Defensive

- [Prowler](https://github.com/prowler-cloud/prowler) - AWS security best practices and CIS benchmarks.
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-service security auditing.
- [CloudSploit](https://github.com/aquasecurity/cloudsploit) - Configuration security scanning.
- [Security Monkey](https://github.com/Netflix/security_monkey) - Security configuration monitoring (archived but valuable reference).
- [ElectricEye](https://github.com/jonrau1/ElectricEye) - AWS security posture management with auto-remediation.
- [Prowler Pro](https://prowler.pro/) - Enterprise AWS security platform.

### AWS IAM Analysis

- [PMapper](https://github.com/nccgroup/PMapper) - IAM privilege escalation path analysis.
- [Cloudsplaining](https://github.com/salesforce/cloudsplaining) - AWS IAM policy analysis for least privilege violations.
- [Parliament](https://github.com/duo-labs/parliament) - AWS IAM linting library.
- [IAM Access Analyzer](https://aws.amazon.com/iam/access-analyzer/) - Native AWS service for IAM policy analysis.
- [enumerate-iam](https://github.com/andresriancho/enumerate-iam) - Enumerate IAM permissions without logs.
- [IAMFinder](https://github.com/prisma-cloud/IAMFinder) - Enumerate and identify IAM roles.
- [aws-iam-tester](https://github.com/darkbitio/aws-iam-tester) - Test IAM permissions systematically.
- [iamlive](https://github.com/iann0036/iamlive) - Generate IAM policies from AWS calls.

### S3 Security

- [S3Scanner](https://github.com/sa7mon/S3Scanner) - Scan for open S3 buckets.
- [bucket-finder](https://github.com/gwen001/s3-buckets-finder) - S3 bucket discovery tool.
- [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump) - Quickly enumerate S3 buckets.
- [s3-inspector](https://github.com/clario-tech/s3-inspector) - Check S3 bucket permissions.
- [S3cret Scanner](https://github.com/Eilonh/s3crets_scanner) - Search for secrets in S3 buckets.

### Native AWS Services

- [AWS Security Hub](https://aws.amazon.com/security-hub/) - Centralized security findings aggregation.
- [Amazon GuardDuty](https://aws.amazon.com/guardduty/) - Threat detection service.
- [AWS Config](https://aws.amazon.com/config/) - Configuration compliance monitoring.
- [Amazon Inspector](https://aws.amazon.com/inspector/) - Vulnerability assessment.
- [Amazon Macie](https://aws.amazon.com/macie/) - Data security and privacy.
- [AWS CloudTrail](https://aws.amazon.com/cloudtrail/) - API activity logging.
- [Amazon Detective](https://aws.amazon.com/detective/) - Security investigation.

---

## Azure Security Tools

### Azure Offensive

- [AzureHound](https://github.com/BloodHoundAD/AzureHound) - Azure data collector for BloodHound.
- [ROADtools](https://github.com/dirkjanm/ROADtools) - Azure AD exploration framework.
- [MicroBurst](https://github.com/NetSPI/MicroBurst) - PowerShell toolkit for Azure security.
- [Stormspotter](https://github.com/Azure/Stormspotter) - Azure Red Team tool for graphing resources.
- [PowerZure](https://github.com/hausec/PowerZure) - PowerShell framework for Azure security.
- [AADInternals](https://github.com/Gerenios/AADInternals) - Azure AD administration PowerShell module.

### Azure Defensive

- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Azure security configuration review.
- [CloudSploit](https://github.com/aquasecurity/cloudsploit) - Azure resource scanning.
- [Prowler](https://github.com/prowler-cloud/prowler) - Azure security assessment.
- [ScubaGear](https://github.com/cisagov/ScubaGear) - M365 security configuration assessment.
- [AzureSecurityBenchmark](https://github.com/Azure/azure-policy) - Azure security policies.
- [Monkey365](https://github.com/silverhack/monkey365) - Azure and Microsoft 365 security scanner.

### IAM/Entra ID Analysis

- [AzureADRecon](https://github.com/adrecon/AzureADRecon) - Azure AD enumeration and reconnaissance.
- [ROADtools](https://github.com/dirkjanm/ROADtools) - Azure AD exploration and analysis.
- [AADInternals](https://github.com/Gerenios/AADInternals) - Azure AD administration and security.
- [AzureHound](https://github.com/BloodHoundAD/AzureHound) - Attack path analysis for Azure AD.

### Native Azure Services

- [Microsoft Defender for Cloud](https://azure.microsoft.com/en-us/products/defender-for-cloud/) - Cloud security posture management.
- [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel/) - Cloud-native SIEM.
- [Azure Policy](https://azure.microsoft.com/en-us/products/azure-policy/) - Governance and compliance.
- [Azure Monitor](https://azure.microsoft.com/en-us/products/monitor/) - Observability and diagnostics.

---

## GCP Security Tools

### GCP Offensive

- [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute) - GCP bucket enumeration.
- [gcp_enum](https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_enum) - GCP enumeration tool.
- [gcp-iam-collector](https://github.com/marcin-kolda/gcp-iam-collector) - Collect and analyze GCP IAM data.
- [Hayat](https://github.com/DenizParlak/hayat) - GCP penetration testing tool.

### GCP Defensive

- [Prowler](https://github.com/prowler-cloud/prowler) - GCP security posture assessment.
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - GCP multi-service auditing.
- [CloudSploit](https://github.com/aquasecurity/cloudsploit) - GCP configuration scanning.
- [Forseti Security](https://github.com/forseti-security/forseti-security) - GCP security tool suite (archived).
- [gcp-audit](https://github.com/spotify/gcp-audit) - GCP security auditing.

### Native GCP Services

- [Security Command Center](https://cloud.google.com/security-command-center) - Security and risk management.
- [Cloud Asset Inventory](https://cloud.google.com/asset-inventory) - Asset metadata and relationships.
- [VPC Service Controls](https://cloud.google.com/vpc-service-controls) - Service perimeter security.
- [Binary Authorization](https://cloud.google.com/binary-authorization) - Container image verification.
- [Cloud Audit Logs](https://cloud.google.com/logging/docs/audit) - Activity logging.

---

## Container & Kubernetes Security

### Image Scanning

- [Trivy](https://github.com/aquasecurity/trivy) - Comprehensive vulnerability scanner for containers.
- [Grype](https://github.com/anchore/grype) - Vulnerability scanner for container images.
- [Clair](https://github.com/quay/clair) - Static analysis of container vulnerabilities.
- [Anchore](https://github.com/anchore/anchore-engine) - Container image analysis and policy enforcement.
- [Snyk Container](https://snyk.io/product/container-vulnerability-management/) - Container vulnerability management.

### Runtime Security

- [Falco](https://github.com/falcosecurity/falco) - Cloud-native runtime security.
- [Sysdig](https://sysdig.com/) - Container security and monitoring platform.
- [Tetragon](https://github.com/cilium/tetragon) - eBPF-based security observability.
- [KubeArmor](https://github.com/kubearmor/KubeArmor) - Container-aware runtime security.
- [Tracee](https://github.com/aquasecurity/tracee) - Linux runtime security with eBPF.

### Kubernetes Audit & Compliance

- [kube-bench](https://github.com/aquasecurity/kube-bench) - CIS Kubernetes Benchmark checks.
- [Kubescape](https://github.com/kubescape/kubescape) - Kubernetes security platform with NSA and MITRE frameworks.
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) - Kubernetes penetration testing.
- [Polaris](https://github.com/FairwindsOps/polaris) - Best practices validation.
- [Popeye](https://github.com/derailed/popeye) - Kubernetes cluster sanitizer.
- [kube-linter](https://github.com/stackrox/kube-linter) - Static analysis for Kubernetes manifests.
- [kubeaudit](https://github.com/Shopify/kubeaudit) - Audit Kubernetes clusters for security concerns.
- [Kubei](https://github.com/Portshift/kubei) - Kubernetes runtime vulnerability scanner.

---

## IAM Analysis

- [Nubicustos](https://github.com/Su1ph3r/Nubicustos) - Integrated IAM analysis with PMapper and Cloudsplaining for privilege escalation paths.
- [PMapper](https://github.com/nccgroup/PMapper) - AWS IAM privilege escalation path analysis.
- [Cloudsplaining](https://github.com/salesforce/cloudsplaining) - AWS managed policy analysis.
- [Parliament](https://github.com/duo-labs/parliament) - AWS IAM linting.
- [enumerate-iam](https://github.com/andresriancho/enumerate-iam) - IAM permission enumeration.
- [IAMFinder](https://github.com/prisma-cloud/IAMFinder) - IAM role identification.
- [iam-policy-json-to-terraform](https://github.com/flosell/iam-policy-json-to-terraform) - Convert IAM policies to Terraform.

---

## Secrets Scanning

- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - 700+ secret detectors with API verification.
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Fast git secrets scanner with extensive rule set.
- [detect-secrets](https://github.com/Yelp/detect-secrets) - Secrets detection in codebases.
- [git-secrets](https://github.com/awslabs/git-secrets) - Prevent committing secrets to git.
- [ggshield](https://github.com/GitGuardian/ggshield) - GitGuardian CLI for secrets detection.
- [whispers](https://github.com/Skyscanner/whispers) - Static code analysis for secrets.
- [repo-supervisor](https://github.com/nickolashkraus/repo-supervisor) - Scan repositories for secrets.

---

## Compliance & Governance

- [Nubicustos](https://github.com/Su1ph3r/Nubicustos) - CIS, SOC2, PCI-DSS framework compliance with historical tracking.
- [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian) - Policy-as-code for cloud governance.
- [Prowler](https://github.com/prowler-cloud/prowler) - CIS benchmark compliance checks.
- [OpenSCAP](https://www.open-scap.org/) - Security Content Automation Protocol implementation.
- [InSpec](https://github.com/inspec/inspec) - Infrastructure testing and compliance automation.
- [Dome9](https://dome9.com/) - Cloud security posture management (Check Point).
- [Fugue](https://www.fugue.co/) - Cloud security and compliance automation.

---

## Serverless Security

- [Serverless Goat](https://github.com/OWASP/Serverless-Goat) - OWASP serverless vulnerable application.
- [DVSA](https://github.com/OWASP/DVSA) - Damn Vulnerable Serverless Application.
- [Protego](https://www.protego.io/) - Serverless security platform.
- [PureSec](https://www.puresec.io/) - Serverless security (acquired by Palo Alto).
- [Sls-dev-tools](https://github.com/Theodo-UK/sls-dev-tools) - Serverless development toolkit.

---

## Training Labs & Vulnerable Environments

### AWS

- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) - "Vulnerable by design" AWS deployment tool.
- [Sadcloud](https://github.com/nccgroup/sadcloud) - Terraform for insecure AWS infrastructure.
- [TerraGoat](https://github.com/bridgecrewio/terragoat) - Vulnerable Terraform repository.
- [AWSGoat](https://github.com/ine-labs/AWSGoat) - Vulnerable AWS infrastructure.
- [flaws.cloud](http://flaws.cloud/) - AWS CTF challenges.
- [flaws2.cloud](http://flaws2.cloud/) - AWS CTF challenges (advanced).

### Azure

- [AzureGoat](https://github.com/ine-labs/AzureGoat) - Vulnerable Azure infrastructure.
- [Purple Cloud](https://github.com/iknowjason/PurpleCloud) - Azure Active Directory lab.

### GCP

- [GCPGoat](https://github.com/ine-labs/GCPGoat) - Vulnerable GCP infrastructure.
- [thunder-ctf](https://github.com/NicholasSpringer/thunder-ctf) - GCP CTF framework.

### Kubernetes

- [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) - Vulnerable Kubernetes cluster.
- [kube-security-lab](https://github.com/raesene/kube_security_lab) - Kubernetes security testing lab.

### Multi-Cloud

- [WrongSecrets](https://github.com/OWASP/wrongsecrets) - Demonstrate secret management failures across AWS, Azure, and GCP.
- [Pwned Labs](https://pwnedlabs.io/) - Free hosted cloud security labs.
- [HackTheBox Cloud Labs](https://www.hackthebox.com/business/cloud-labs) - Cloud penetration testing labs.

---

## Contributing

Contributions are welcome! Please read the [Contributing Guidelines](CONTRIBUTING.md) before submitting a pull request.

### How to Contribute

1. Fork the repository
2. Add your tool to the appropriate category
3. Submit a pull request

Missing a tool? [Open an issue](https://github.com/Su1ph3r/awesome-cloud-security/issues/new?template=add-tool.yml) to suggest it.

---

## Related Resources

- [Awesome AWS](https://github.com/donnemartin/awesome-aws) - General AWS resources
- [Awesome Kubernetes](https://github.com/ramitsurana/awesome-kubernetes) - Kubernetes ecosystem
- [Awesome Pentest](https://github.com/enaqx/awesome-pentest) - Penetration testing resources
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/) - Cloud security guidance

---

## Star History

If you find this list useful, please consider giving it a star. It helps others discover this resource.

[![Star History Chart](https://api.star-history.com/svg?repos=Su1ph3r/awesome-cloud-security&type=Date)](https://star-history.com/#Su1ph3r/awesome-cloud-security&Date)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Found this useful? Give it a ⭐ and share it with your team!</b>
</p>
