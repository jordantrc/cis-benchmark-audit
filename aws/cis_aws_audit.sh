#!/usr/bin/env bash

echo "CIS AWS Benchmark Audit"
echo "Based on version 1.3.0 of the CIS Benchmark."

datestamp=$(date "+%Y%m%d-%H%M")
logfile="aws_audit_$datestamp.log"
section_header="======================================"
prerequisites=("aws" "jq")
echo "Sending script output to ${logfile}"

preprequisite_check() {
    which $1 > /dev/null
    if [[ "$?" -ne 0 ]]; then
        echo "[-] missing prerequisite $1"
        exit 1
    fi
}

audit_requirement() {  
    echo $section_header >> $logfile
    echo "$1" >> $logfile
    eval $2 >> $logfile
    echo "" >> $logfile
}

newline_delimited_to_array() {
    SAVEIFS=$IFS   # Save current IFS
    IFS=$'\n'      # Change IFS to new line
    array=($1) # split to array
    IFS=$SAVEIFS   # Restore IFS
}

tab_delimited_to_array() {
    SAVEIFS=$IFS   # Save current IFS
    IFS=$'\t'      # Change IFS to new line
    array=($1) # split to array
    IFS=$SAVEIFS   # Restore IFS
}

# check that prerequisites are installed
for i in "${!prerequisites[@]}"
do
    preprequisite_check ${prerequisites[$i]}
done

# show information about AWS CLI configuration
echo $section_header >> $logfile
echo `date` >> $logfile
echo "" >> $logfile
echo "AWS Configurations:" >> $logfile
aws configure list >> $logfile
echo "" >> $logfile

# list enabled regions
aws_regions=( $(aws ec2 describe-regions --output table | grep "amazonaws.com" | awk '{print $6}') )
echo "Discovered ${#aws_regions[@]} enabled AWS regions:" >> $logfile
for i in "${!aws_regions[@]}"
do
    echo "$i: ${aws_regions[$i]}" >> $logfile
done
users=( $(aws iam list-users --query "Users[*].UserName" --output text | tr '\t' '\n') )
echo "Discovered ${#users[@]} users:" >> $logfile
for i in "${!users[@]}"
do
    echo "$i: ${users[$i]}" >> $logfile
done

# start auditing
echo $section_header >> $logfile
echo "LEVEL 1 SECTION 1: IAM" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

echo "Generating a credential report..." >> $logfile
output=""
while [ ${#output} -lt 1 ]; do
    output=$(aws iam generate-credential-report | grep "State" | grep "COMPLETE")
    sleep 2
done

audit_requirement "1.4 - Ensure no root user account access key exists" "aws iam get-account-summary | grep \"AccountAccessKeysPresent\""

audit_requirement "1.5 - Ensure MFA is enabled for the \"root user\" account" "aws iam get-account-summary | grep \"AccountMFAEnabled\""

audit_requirement "1.7 - Eliminate use of the root user for administrative and daily tasks" "aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,5,11,16"

audit_requirement "1.8 - 1.9 - AWS IAM Password policy requires minimum length of 14 or greater, prevents reuse" "aws iam get-account-password-policy"

audit_requirement "1.10 - Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password" "aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,8"

audit_requirement "1.11 - Do not setup access keys during initial user setup for all IAM users that have a console password" "aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,9,11,14,16"

audit_requirement "1.12 - Ensure credentials unused for 90 days or greater are disabled" "aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,5,6,9,10,11,14,15,16"

echo $section_header >> $logfile
echo "Requirement 1.13 - Ensure there is only one active access key available for any single IAM user" >> $logfile
for i in "${!users[@]}"
do
    echo "Access Keys for ${users[$i]}:" >> $logfile
    aws iam list-access-keys --user-name ${users[$i]} >> $logfile
done

audit_requirement "1.14 - Ensure access keys are rotated every 90 days or less" "aws iam get-credential-report --query 'Content' --output text | base64 -d"

echo $section_header >> $logfile
echo "1.15 - Ensure IAM Users Receive Permissions Only Through Groups" >> $logfile
for i in "${!users[@]}"; do
    echo "IAM attached user policies for ${users[$i]}:" >> $logfile
    aws iam list-attached-user-policies --user-name ${users[$i]} >> $logfile
    aws iam list-user-policies --user-name ${users[$i]} >> $logfile
done

echo $section_header >> $logfile
echo "1.16 - Ensure IAM policies that allow full \"*:*\" administrative privileges are not attached" >> $logfile
policy_arns=$(aws iam list-policies --only-attached | jq '.Policies[].Arn, .Policies[].DefaultVersionId')
policy_arns=($policy_arns)
len_policy_arns=${#policy_arns[@]}
if [[ ${len_policy_arns} -eq 0 ]]; then
    echo "no attached policies found" >> $logfile
else
    num_policies=$(expr ${len_policy_arns} / 2)
    last_index=$(expr ${num_policies} - 1)
    echo "found ${num_policies} attached policies" >> $logfile
    for i in $(seq 0 $last_index); do
        version_index=$(expr $i + $num_policies)
        policy_arn=$(echo ${policy_arns[$i]} | tr -d '"')
        policy_version=$(echo ${policy_arns[$version_index]} | tr -d '"')
        echo "policy arn: ${policy_arn}, version: ${policy_version}" >> $logfile
        aws iam get-policy-version --policy-arn ${policy_arn} --version-id ${policy_version} >> $logfile
    done
fi

audit_requirement "1.17 - Ensure a support role has been created to manage incidents with AWS Support" "aws iam list-policies --query \"Policies[?PolicyName == 'AWSSupportAccess']\";\
aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess"

audit_requirement "1.19 - Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed" "aws iam list-server-certificates"

echo $section_header >> $logfile
echo "Requirement 1.20 - Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'" >> $logfile
buckets=( $(aws s3 ls | cut -d " " -f 3) )
for i in "${!buckets[@]}"; do
    echo "bucket ${buckets[$i]}:" >> $logfile
    aws s3api get-public-access-block --bucket ${buckets[$i]} >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "1.21 - Ensure that IAM Access analyzer is enabled" >> $logfile
analyzers=( $(aws accessanalyzer list-analyzers | grep "\"name\":" | awk '{print $2}' | cut -d, -f 1 | tr -d '"') )
for i in "${!analyzers[@]}"; do
    echo "analyzer ${analyzers[$i]}:" >> $logfile
    aws accessanalyzer get-analyzer --analyzer-name ${analyzers[$i]} | grep status >> $logfile
done

echo $section_header >> $logfile
echo "LEVEL 1 SECTION 2: Storage" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

echo $section_header >> $logfile
echo "Requirement 2.1.1 - Ensure all S3 buckets employ encryption-at-rest" >> $logfile
for i in "${!buckets[@]}"; do
    echo "bucket ${buckets[$i]}:" >> $logfile
    aws s3api get-bucket-encryption --bucket ${buckets[$i]} >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "2.2.1 - Ensure EBS volume encryption is enabled" >> $logfile
for i in "${!aws_regions[@]}"; do
    echo "region ${aws_regions[$i]}:" >> $logfile
    aws --region ${aws_regions[$i]} ec2 get-ebs-encryption-by-default >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "LEVEL 1 SECTION 3: Logging" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

echo $section_header >> $logfile
echo "3.1 - Ensure CloudTrail is enabled in all regions" >> $logfile
trails=( $(aws cloudtrail describe-trails --query 'trailList[*].Name' | grep '"' | awk '{print $1}' | tr -d '"' | tr -d ","))
for i in "${!trails[@]}"; do
    echo "trail ${trails[$i]}:" >> $logfile
    aws cloudtrail get-trail-status --name ${trails[$i]} >> $logfile 2>&1
    aws cloudtrail get-event-selectors --trail-name ${trails[$i]} >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "3.3 - Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible" >> $logfile
cloudtrail_buckets=( $(aws cloudtrail describe-trails --query 'trailList[*].S3BucketName' | grep '"' | awk '{print $1}' | tr -d '"' | tr -d ","))
for i in "${!cloudtrail_buckets[@]}"; do
    echo "cloudtrail bucket ${cloudtrail_buckets[$i]}:" >> $logfile
    aws s3api get-bucket-acl --bucket ${cloudtrail_buckets[$i]} --query "Grants[?Grantee.URI== 'https://acs.amazonaws.com/groups/global/AllUsers']" >> $logfile 2>&1
    aws s3api get-bucket-acl --bucket ${cloudtrail_buckets[$i]} --query "Grants[?Grantee.URI== 'https://acs.amazonaws.com/groups/global/Authenticated Users']" >> $logfile 2>&1
    aws s3api get-bucket-policy --bucket ${cloudtrail_buckets[$i]} >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "3.4 - Ensure CloudTrail trails are integrated with CloudWatch Logs" >> $logfile
for i in "${!trails[@]}"; do
    echo "trail ${trails[$i]}:" >> $logfile
    aws cloudtrail get-trail-status --name ${trails[$i]} >> $logfile 2>&1
done

audit_requirement "3.5 - Ensure AWS Config is enabled in all regions" "aws configservice describe-configuration-recorders"

echo $section_header >> $logfile
echo "3.6 - Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket" >> $logfile
for i in "${!cloudtrail_buckets[@]}"; do
    echo "cloudtrail bucket ${cloudtrail_buckets[$i]}:" >> $logfile
    aws s3api get-bucket-logging --bucket ${cloudtrail_buckets[$i]} >> $logfile 2>&1
done

# Level 2 Audit
echo $section_header >> $logfile
echo "LEVEL 2 SECTION 1: IAM" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

audit_requirement "1.6 - Ensure hardware MFA is enabled for the \"root user\" account" "aws iam list-virtual-mfa-devices"

echo $section_header >> $logfile
echo "LEVEL 2 SECTION 2: STORAGE" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

echo $section_header >> $logfile
echo "2.1.1 - Ensure all S3 buckets employ encryption-at-rest" >> $logfile
for i in "${!buckets[@]}"; do
    echo "bucket ${buckets[$i]}:" >> $logfile
    aws s3api get-bucket-encryption --bucket ${buckets[$i]} >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "2.1.2 - Ensure S3 Bucket Policy allows HTTPS requests" >> $logfile
for i in "${!buckets[@]}"; do
    echo "bucket ${buckets[$i]}:" >> $logfile
    aws s3api get-bucket-policy --bucket ${buckets[$i]} | grep aws:SecureTransport >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "2.2.1 - Ensure EBS volume encryption is enabled" >> $logfile
for i in "${!aws_regions[@]}"; do
    echo "region ${aws_regions[$i]}:" >> $logfile
    aws --region ${aws_regions[$i]} ec2 get-ebs-encryption-by-default >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "LEVEL 2 SECTION 3: LOGGING" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

audit_requirement "3.2 - Ensure CloudTrail log file validation is enabled" "aws cloudtrail describe-trails"

audit_requirement "3.7 - Ensure CloudTrail logs are encrypted at rest using KMS CMKs" "aws cloudtrail describe-trails"

echo $section_header >> $logfile
echo "3.8 - Ensure rotation for customer created CMKs is enabled"  >> $logfile
keys=( $(aws kms list-keys --query 'Keys[*].KeyId' | grep '"' | awk '{print $1}' | tr -d '"' | tr -d ',') )
for i in "${!keys[@]}"; do
    echo "key ${keys[$i]}:" >> $logfile
    aws kms get-key-rotation-status --key-id ${keys[$i]} >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "3.10-3.11 - Ensure that Object-level logging for read/write events is enabled for S3 bucket"  >> $logfile
for i in "${!aws_regions[@]}"; do
    region_trails=( $(aws cloudtrail list-trails --region ${aws_regions[$i]} --query Trails[*].Name | grep '"' | awk '{print $1}' | tr -d '"' | tr -d ',') )
    for j in "${!region_trails[@]}"; do
        echo "region ${aws_regions[$i]}, trail ${region_trails[$j]}:" >> $logfile
        aws cloudtrail get-event-selectors --region ${aws_regions[$i]} --trail-name ${region_trails[$j]} --query EventSelectors[*].DataResources[] >> $logfile 2>&1
    done
done

echo $section_header >> $logfile
echo "LEVEL 2 SECTION 4: MONITORING" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile