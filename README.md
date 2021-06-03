# CIS Benchmark Audits

## AWS

### Prerequisites

1. [AWS CLI](https://aws.amazon.com/cli/)
2. [jq](https://stedolan.github.io/jq/)

**jq** can usually be installed via Linux distribution package manager.

### AWS Setup and Execution

First configure the aws cli with the appropriate Access Key, Secret Key, and ensure a default region is set. It does not matter which region you select, but the default region has to be set for certain aws CLI commands.

```bash
aws configure
AWS Access Key ID [None]: AKI*****************
AWS Secret Access Key [None]: ****************************************
Default region name [None]: us-east-1
Default output format [None]:
```

Once configured, simply run the script. The output will be sent to a single file, *aws_audit_YYYYMMDD-HHMM.log*.

```bash
./cis_aws_audit.sh
CIS AWS Benchmark Audit
Based on version 1.3.0 of the CIS Benchmark.
Sending script output to aws_audit_20210527-2038.log
AUDITING SECTION 1: IAM
AUDITING SECTION 2: Storage
AUDITING SECTION 3: Logging
...
```

## Azure

### Azure Prerequisites

1. [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
2. [jq](https://stedolan.github.io/jq/)
3. [curl](https://curl.se/)

### Azure Setup and Execution

1. Login with the az cli command `az login`.
2. Run the script to create the benchmark log file.

```bash
./cis_azure_audit.sh
CIS Azure Benchmark Audit
Based on version 1.3.0 of the CIS Benchmark.
Sending script output to azure_audit_20210602-2011.log
LEVEL 1 SECTION 1: IAM
LEVEL 1 SECTION 2: Security Center
LEVEL 1 SECTION 3: Storage Accounts
LEVEL 1 SECTION 4: Database Services
LEVEL 1 SECTION 5: Logging and Monitoring
LEVEL 1 SECTION 6: Networking
LEVEL 1 SECTION 7: Virtual Machines
LEVEL 1 SECTION 8: Other Security Concerns
LEVEL 2 SECTION 2: Security Center
LEVEL 2 SECTION 3: Storage Accounts
LEVEL 2 SECTION 4: Database Services
LEVEL 2 SECTION 7: Virtual Machines
LEVEL 2 SECTION 9: AppService
Script complete
```