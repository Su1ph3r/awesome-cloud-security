# Awesome Cloud Security [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> A curated list of cloud security tools for AWS, Azure, GCP, and Kubernetes.

Whether you're a penetration tester, cloud security engineer, DevSecOps professional, or security researcher, this list provides tools for offensive security, defensive security, compliance, and IAM analysis.

## Contents

- [Multi-Cloud Security](#multi-cloud-security)
- [Attack Path Analysis](#attack-path-analysis)
- [AWS Security](#aws-security)
- [Azure Security](#azure-security)
- [GCP Security](#gcp-security)
- [Container and Kubernetes Security](#container-and-kubernetes-security)
- [IAM Analysis](#iam-analysis)
- [Secrets Scanning](#secrets-scanning)
- [Compliance and Governance](#compliance-and-governance)
- [Infrastructure as Code Security](#infrastructure-as-code-security)
- [Serverless Security](#serverless-security)
- [Training Labs](#training-labs)

## Multi-Cloud Security

- [Nubicustos](https://github.com/Su1ph3r/Nubicustos) - Unified security platform orchestrating 24+ tools with attack path analysis and compliance across AWS, Azure, GCP, and Kubernetes.
- [Prowler](https://github.com/prowler-cloud/prowler) - Security assessment tool for AWS, Azure, GCP, and Kubernetes with CIS benchmark checks.
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing tool supporting AWS, Azure, GCP, Alibaba Cloud, and Oracle Cloud.
- [CloudSploit](https://github.com/aquasecurity/cloudsploit) - Cloud security configuration scanner for AWS, Azure, GCP, and Oracle Cloud.
- [CloudQuery](https://github.com/cloudquery/cloudquery) - Open source cloud asset inventory with SQL-based policy engine.
- [Steampipe](https://github.com/turbot/steampipe) - Query cloud APIs using SQL with pre-built compliance mods.
- [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian) - Rules engine for cloud security, cost optimization, and governance.
- [Magpie](https://github.com/openraven/magpie) - Cloud security posture management with data discovery.
- [Cartography](https://github.com/lyft/cartography) - Graph-based asset inventory and relationship mapping.
- [cloudlist](https://github.com/projectdiscovery/cloudlist) - Multi-cloud asset listing tool.
- [Resoto](https://github.com/someengineering/resoto) - Infrastructure inventory with search and analytics.

## Attack Path Analysis

- [CloudFox](https://github.com/BishopFox/cloudfox) - AWS attack surface enumeration for penetration testers.
- [PMapper](https://github.com/nccgroup/PMapper) - AWS IAM privilege escalation path finder using graph analysis.
- [Cloudmapper](https://github.com/duo-labs/cloudmapper) - AWS environment visualization and analysis.
- [AzureHound](https://github.com/BloodHoundAD/AzureHound) - Azure data collector for BloodHound attack path analysis.

## AWS Security

### Offensive

- [Pacu](https://github.com/RhinoSecurityLabs/pacu) - AWS exploitation framework for penetration testing.
- [aws_pwn](https://github.com/dagrz/aws_pwn) - Collection of AWS penetration testing tools.
- [Endgame](https://github.com/salesforce/endgame) - AWS resource policy exploitation tool for privilege escalation.
- [Weirdaal](https://github.com/carnal0wnage/weirdAAL) - AWS attack library.
- [ccat](https://github.com/RhinoSecurityLabs/ccat) - Cloud Container Attack Tool.
- [Nimbostratus](https://github.com/andresriancho/nimbostratus) - AWS security assessment tool.

### Defensive

- [ElectricEye](https://github.com/jonrau1/ElectricEye) - AWS security posture management with auto-remediation.
- [Security Monkey](https://github.com/Netflix/security_monkey) - Security configuration monitoring.

### IAM

- [Cloudsplaining](https://github.com/salesforce/cloudsplaining) - AWS IAM policy analysis for least privilege violations.
- [Parliament](https://github.com/duo-labs/parliament) - AWS IAM linting library.
- [enumerate-iam](https://github.com/andresriancho/enumerate-iam) - Enumerate IAM permissions without logs.
- [IAMFinder](https://github.com/prisma-cloud/IAMFinder) - Enumerate and identify IAM roles.
- [aws-iam-tester](https://github.com/darkbitio/aws-iam-tester) - Test IAM permissions systematically.
- [iamlive](https://github.com/iann0036/iamlive) - Generate IAM policies from AWS calls.

### S3

- [S3Scanner](https://github.com/sa7mon/S3Scanner) - Scan for open S3 buckets.
- [bucket-finder](https://github.com/gwen001/s3-buckets-finder) - S3 bucket discovery tool.
- [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump) - Quickly enumerate S3 buckets.
- [s3-inspector](https://github.com/clario-tech/s3-inspector) - Check S3 bucket permissions.
- [S3cret Scanner](https://github.com/Eilonh/s3crets_scanner) - Search for secrets in S3 buckets.

## Azure Security

### Offensive

- [ROADtools](https://github.com/dirkjanm/ROADtools) - Azure AD exploration framework.
- [MicroBurst](https://github.com/NetSPI/MicroBurst) - PowerShell toolkit for Azure security.
- [Stormspotter](https://github.com/Azure/Stormspotter) - Azure Red Team tool for graphing resources.
- [PowerZure](https://github.com/hausec/PowerZure) - PowerShell framework for Azure security.
- [AADInternals](https://github.com/Gerenios/AADInternals) - Azure AD administration PowerShell module.

### Defensive

- [ScubaGear](https://github.com/cisagov/ScubaGear) - M365 security configuration assessment.
- [Monkey365](https://github.com/silverhack/monkey365) - Azure and Microsoft 365 security scanner.

### IAM

- [AzureADRecon](https://github.com/adrecon/AzureADRecon) - Azure AD enumeration and reconnaissance.

## GCP Security

### Offensive

- [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute) - GCP bucket enumeration.
- [gcp_enum](https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_enum) - GCP enumeration tool.
- [gcp-iam-collector](https://github.com/marcin-kolda/gcp-iam-collector) - Collect and analyze GCP IAM data.
- [Hayat](https://github.com/DenizParlak/hayat) - GCP penetration testing tool.

### Defensive

- [Forseti Security](https://github.com/forseti-security/forseti-security) - GCP security tool suite.
- [gcp-audit](https://github.com/spotify/gcp-audit) - GCP security auditing.

## Container and Kubernetes Security

### Image Scanning

- [Trivy](https://github.com/aquasecurity/trivy) - Comprehensive vulnerability scanner for containers.
- [Grype](https://github.com/anchore/grype) - Vulnerability scanner for container images.
- [Clair](https://github.com/quay/clair) - Static analysis of container vulnerabilities.
- [Anchore](https://github.com/anchore/anchore-engine) - Container image analysis and policy enforcement.

### Runtime Security

- [Falco](https://github.com/falcosecurity/falco) - Cloud-native runtime security.
- [Tetragon](https://github.com/cilium/tetragon) - eBPF-based security observability.
- [KubeArmor](https://github.com/kubearmor/KubeArmor) - Container-aware runtime security.
- [Tracee](https://github.com/aquasecurity/tracee) - Linux runtime security with eBPF.

### Kubernetes Audit

- [kube-bench](https://github.com/aquasecurity/kube-bench) - CIS Kubernetes Benchmark checks.
- [Kubescape](https://github.com/kubescape/kubescape) - Kubernetes security platform with NSA and MITRE frameworks.
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) - Kubernetes penetration testing.
- [Polaris](https://github.com/FairwindsOps/polaris) - Best practices validation.
- [Popeye](https://github.com/derailed/popeye) - Kubernetes cluster sanitizer.
- [kube-linter](https://github.com/stackrox/kube-linter) - Static analysis for Kubernetes manifests.
- [kubeaudit](https://github.com/Shopify/kubeaudit) - Audit Kubernetes clusters for security concerns.
- [Kubei](https://github.com/Portshift/kubei) - Kubernetes runtime vulnerability scanner.

## IAM Analysis

- [iam-policy-json-to-terraform](https://github.com/flosell/iam-policy-json-to-terraform) - Convert IAM policies to Terraform.

## Secrets Scanning

- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - 700+ secret detectors with API verification.
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Fast Git secrets scanner with extensive rule set.
- [detect-secrets](https://github.com/Yelp/detect-secrets) - Secrets detection in codebases.
- [git-secrets](https://github.com/awslabs/git-secrets) - Prevent committing secrets to Git.
- [ggshield](https://github.com/GitGuardian/ggshield) - GitGuardian CLI for secrets detection.
- [whispers](https://github.com/Skyscanner/whispers) - Static code analysis for secrets.

## Compliance and Governance

- [OpenSCAP](https://www.open-scap.org/) - Security Content Automation Protocol implementation.
- [InSpec](https://github.com/inspec/inspec) - Infrastructure testing and compliance automation.

## Infrastructure as Code Security

- [Checkov](https://github.com/bridgecrewio/checkov) - Static analysis for Terraform, CloudFormation, Kubernetes, Helm, and ARM templates.
- [tfsec](https://github.com/aquasecurity/tfsec) - Security scanner for Terraform code.
- [Terrascan](https://github.com/tenable/terrascan) - Static code analyzer for IaC with 500+ policies.
- [KICS](https://github.com/Checkmarx/kics) - Infrastructure as Code scanner for security vulnerabilities.
- [Regula](https://github.com/fugue/regula) - Policy engine for Terraform and CloudFormation using Rego.

## Serverless Security

- [Serverless Goat](https://github.com/OWASP/Serverless-Goat) - OWASP serverless vulnerable application.
- [DVSA](https://github.com/OWASP/DVSA) - Damn Vulnerable Serverless Application.

## Training Labs

### AWS

- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) - Vulnerable by design AWS deployment tool.
- [Sadcloud](https://github.com/nccgroup/sadcloud) - Terraform for insecure AWS infrastructure.
- [TerraGoat](https://github.com/bridgecrewio/terragoat) - Vulnerable Terraform repository.
- [AWSGoat](https://github.com/ine-labs/AWSGoat) - Vulnerable AWS infrastructure.
- [flaws.cloud](http://flaws.cloud/) - AWS CTF challenges.
- [flaws2.cloud](http://flaws2.cloud/) - AWS CTF challenges advanced.

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

## Contributing

Contributions welcome! Read the [contribution guidelines](CONTRIBUTING.md) first.
