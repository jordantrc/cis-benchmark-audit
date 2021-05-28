# CIS Benchmark Audits

## AWS

### Prerequisites

1. [AWS CLI](https://aws.amazon.com/cli/)
2. [jq](https://stedolan.github.io/jq/)

**jq** can usually be installed via Linux distribution package manager.

### Setup and Execution

First configure the aws cli with the appropriate Access Key, Secret Key, and ensure a default region is set. It does not matter which region you select, but the default region has to be set for certain aws CLI commands.

```bash
aws configure
AWS Access Key ID [None]: AKI*****************
AWS Secret Access Key [None]: ****************************************
Default region name [None]: us-east-1
Default output format [None]:
```

Once configured, simply run the script. The output will be sent to a single file, *aws_audt_YYYYMMDD-HHMM.log*.

```bash
./cis_aws_audit.sh
CIS AWS Benchmark Audit
Based on version 1.3.0 of the CIS Benchmark.
Sending script output to aws_audit_20210527-2038.log
AUDITING SECTION 1: IAM
AUDITING SECTION 2: Storage
AUDITING SECTION 3: Logging
```