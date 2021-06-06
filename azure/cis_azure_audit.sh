#!/usr/bin/env bash

echo "CIS Azure Benchmark Audit"
echo "Based on version 1.3.0 of the CIS Benchmark."

datestamp=$(date "+%Y%m%d-%H%M")
logfile="azure_audit_$datestamp.log"
section_header="======================================"
prerequisites=("az" "curl" "jq")
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
    array=($1)     # split to array
    IFS=$SAVEIFS   # Restore IFS
}

tab_delimited_to_array() {
    SAVEIFS=$IFS   # Save current IFS
    IFS=$'\t'      # Change IFS to new line
    array=($1)     # split to array
    IFS=$SAVEIFS   # Restore IFS
}

# check that prerequisites are installed
for i in "${!prerequisites[@]}"
do
    preprequisite_check ${prerequisites[$i]}
done

# show information about Azure CLI configuration
echo $section_header >> $logfile
echo `date` >> $logfile
echo "" >> $logfile
echo "Azure Accounts:" >> $logfile
az account list >> $logfile
echo "" >> $logfile

# list enabled locations
locations=( $(az account list-locations --query '[*].name' | awk '{print $1}' | grep '"' | sed 's/[\"|,]//g') )
echo "Discovered ${#locations[@]} enabled Azure locations:" >> $logfile
for i in "${!locations[@]}"
do
    echo "$i: ${locations[$i]}" >> $logfile
done
users=( $(az ad user list --query "[*].userPrincipalName" | grep '"' | awk '{print $1}' | sed 's/[\"|,]//g') )
echo "Discovered ${#users[@]} users:" >> $logfile
for i in "${!users[@]}"
do
    echo "$i: ${users[$i]}" >> $logfile
done

echo $section_header >> $logfile
echo "LEVEL 1 SECTION 1: IAM" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

audit_requirement "1.3 - Ensure guest users are reviewed on a monthly basis" "az ad user list --query \"[?userType=='Guest']\""

echo $section_header >> $logfile
echo "LEVEL 1 SECTION 2: Security Center" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

audit_requirement "2.11 - Ensure that 'Automatic provisioning of monitoring agent' is set to 'On'" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview' | jq '.|.value[] | select(.name==\"default\")'|jq '.properties.autoProvision'"

audit_requirement "2.12 - Ensure any of the ASC Default policy setting is not set to 'Disabled'" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn?api-version=2018-05-01' | jq"

audit_requirement "2.13 - Ensure 'Additional email addresses' is configured with a security contact email" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/securityContacts?api-version=2017-08-01-preview' | jq " #'.|.value[] | select(.name==\"default\")'|jq '.properties.email'"

audit_requirement "2.14 - Ensure that 'Notify about alerts with the following severity' is set to 'High'" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/securityContacts?api-version=2017-08-01-preview' | jq " # '.|.value[] | select(.name==\"default1\")'|jq '.properties.alertNotifications'"

audit_requirement "2.15 - Ensure that 'All users with the following roles' is set to 'Owner'" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/securityContacts?api-version=2017-08-01-preview' | jq " # '.|.value[] | select(.name==\"default1\")'|jq '.properties.alertsToAdmins'"

echo $section_header >> $logfile
echo "LEVEL 1 SECTION 3: Storage Accounts" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

audit_requirement "3.1 - az storage account list --query '[*].[name,enableHttpsTrafficOnly]'"

echo $section_header >> $logfile
echo "3.2 - Ensure that storage account access keys are periodically regenerated" >> $logfile
storage_accounts=( $(az storage account list --query '[*].id' | grep '"' | awk '{print $1}' | sed 's/[\"|,]//g') )
for i in "${!storage_accounts[@]}"; do
    echo "storage account: ${storage_accounts[$i]}:" >> $logfile
    az monitor activity-log list --namespace Microsoft.Storage --offset 90d --query "[?contains(authorization.action, 'regenerateKey')]" --resource-id ${storage_accounts[$i]} >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "LEVEL 1 SECTION 4: Database Services" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

resource_groups=( $(az group list --query '[*].name' | grep '"' | awk '{print $1}' | sed 's/[\"|,]//g') )

echo $section_header >> $logfile
echo "4.3.1, 4.3.3 - 4.3.8 - PostgreSQL database server configuration" >> $logfile
postgres_servers=( $(az postgres server list | grep '"' | awk '{print $1}' | sed 's/[\"|,]//g') )
for i in "${!resource_groups[@]}"; do
    for j in "${!postgres_servers[@]}"; do
        echo "resource group ${resource_groups[$i]}, postgres server ${postgres_servers[$i]}:" >> $logfile
        az postgres server show --resource-group ${resource_groups[$i]} --name ${postgres_servers[$i]} --query sslEnforcement >> $logfile 2>&1
        az postgres server configuration show --resource-group ${resource_groups[$i]} --server-name ${postgres_servers[$i]} --name log_checkpoints >> $logfile 2>&1
        az postgres server configuration show --resource-group ${resource_groups[$i]} --server-name ${postgres_servers[$i]} --name log_connections >> $logfile 2>&1
        az postgres server configuration show --resource-group ${resource_groups[$i]} --server-name ${postgres_servers[$i]} --name log_disconnections >> $logfile 2>&1
        az postgres server configuration show --resource-group ${resource_groups[$i]} --server-name ${postgres_servers[$i]} --name connection_throttling >> $logfile 2>&1
        az postgres server configuration show --resource-group ${resource_groups[$i]} --server-name ${postgres_servers[$i]} --name log_retention_days >> $logfile 2>&1
        az postgres server firewall-rule list --resource-group ${resource_groups[$i]} --server ${postgres_servers[$i]} >> $logfile 2>&1
    done
done

echo $section_header >> $logfile
echo "4.3.2 - Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server" >> $logfile
mysql_servers=( $(az mysql server list | grep '"' | awk '{print $1}' | sed 's/[\"|,]//g') )
for i in "${!resource_groups[@]}"; do
    for j in "${!mysql_servers[@]}"; do
        echo "resource group ${resource_groups[$i]}, MySQL server ${mysql_servers[$i]}:" >> $logfile
        az mysql server show --resource-group ${resource_groups[$i]} --name ${mysql_servers[$i]} --query sslEnforcement >> $logfile 2>&1
    done
done

echo $section_header >> $logfile
echo "LEVEL 1 SECTION 5: Logging and Monitoring" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

echo $section_header >> $logfile
echo "5.1.3 - Ensure the storage container storing the activity logs is not publicly accessible" >> $logfile
storage_account_ids=( $(az monitor log-profiles list --query '[*].storageAccountId' | grep '"' | awk '{print $1}' | sed 's/[\"|,]//g') )
for i in "${!storage_account_ids[@]}"; do
    echo "storage account id ${storage_account_ids[$i]}:" >> $logfile
    az storage container list --account-name ${storage_account_ids[$i]} --query "[?name=='insights-operational-logs']" >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "5.1.5 - Ensure that logging for Azure KeyVault is 'Enabled'" >> $logfile
keyvaults=( $(az keyvault list --query '[*].id' | grep '"' | awk '{print $1}' | sed 's/[\"|,]//g') )
for i in "${!keyvaults[@]}"; do
    echo "key vault id ${keyvaults[$i]}:" >> $logfile
    az monitor diagnostic-settings list --resource ${keyvaults[$i]} >> $logfile 2>&1
done

audit_requirement "5.2.1 - Ensure that Activity Log Alert exists for Create Policy Assignment" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/microsoft.insights/activityLogAlerts?api-version=2017-04-01' | jq '.|.value[]|{location:.location,scopes:.properties.scopes,\"condition\":.properties.condition.allOf|.[]|select(.field==\"operationName\" and .equals==\"microsoft.authorization/policyassignments/write\"),enabled:.properties.enabled}'"

audit_requirement "5.2.2 - Ensure that Activity Log Alert exists for Delete Policy Assignment" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/microsoft.insights/activityLogAlerts?api-version=2017-04-01' | jq '.|.value[]|{location:.location,scopes:.properties.scopes,\"condition\":.properties.condition.allOf|.[]|select(.field==\"operationName\" and .equals==\"microsoft.authorization/policyassignments/delete\"),enabled:.properties.enabled}'"

audit_requirement "5.2.3 - Ensure that Activity Log Alert exists for Create or Update Network Security Group" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/microsoft.insights/activityLogAlerts?api-version=2017-04-01' | jq '.|.value[]|{location:.location,scopes:.properties.scopes,\"condition\":.properties.condition.allOf|.[]|select(.field==\"operationName\" and .equals==\"microsoft.network/networksecuritygroups/write\"),enabled:.properties.enabled}'"

audit_requirement "5.2.4 - Ensure that Activity Log Alert exists for Delete Network Security Group" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/microsoft.insights/activityLogAlerts?api-version=2017-04-01' | jq '.|.value[]|{location:.location,scopes:.properties.scopes,\"condition\":.properties.condition.allOf|.[]|select(.field==\"operationName\" and .equals==\"microsoft.network/networksecuritygroups/delete\"),enabled:.properties.enabled}'"

audit_requirement "5.2.5 - Ensure that Activity Log Alert exists for Create or Update Network Security Group Rule" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/microsoft.insights/activityLogAlerts?api-version=2017-04-01' | jq '.|.value[]|{location:.location,scopes:.properties.scopes,\"condition\":.properties.condition.allOf|.[]|select(.field==\"operationName\" and .equals==\"microsoft.network/networksecuritygroups/securityrules/write\"),enabled:.properties.enabled}'"

audit_requirement "5.2.6 - Ensure that activity log alert exists for the Delete Network Security Group Rule" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/microsoft.insights/activityLogAlerts?api-version=2017-04-01' | jq '.|.value[]|{location:.location,scopes:.properties.scopes,\"condition\":.properties.condition.allOf|.[]|select(.field==\"operationName\" and .equals==\"microsoft.network/networksecuritygroups/securityrules/delete\"),enabled:.properties.enabled}'"

audit_requirement "5.2.7 - Ensure that Activity Log Alert exists for Create or Update Security Solution" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/microsoft.insights/activityLogAlerts?api-version=2017-04-01' | jq '.|.value[]|{location:.location,scopes:.properties.scopes,\"condition\":.properties.condition.allOf|.[]|select(.field==\"operationName\" and .equals==\"microsoft.security/securitysolutions/write\"),enabled:.properties.enabled}'"

audit_requirement "5.2.8 - Ensure that Activity Log Alert exists for Delete Security Solution" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/microsoft.insights/activityLogAlerts?api-version=2017-04-01' | jq '.|.value[]|{location:.location,scopes:.properties.scopes,\"condition\":.properties.condition.allOf|.[]|select(.field==\"operationName\" and .equals==\"microsoft.security/securitysolutions/delete\"),enabled:.properties.enabled}'"

audit_requirement "5.2.9 - Ensure that Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/microsoft.insights/activityLogAlerts?api-version=2017-04-01' | jq '.|.value[]|{location:.location,scopes:.properties.scopes,\"condition\":.properties.condition.allOf|.[]|select(.field==\"operationName\" and .equals==\"microsoft.sql/servers/firewallrules/write\"),enabled:.properties.enabled}'"

echo $section_header >> $logfile
echo "5.3 - Ensure that Diagnostic Logs are enabled for all services which support it." >> $logfile
resources=( $(az resource list | jq '.[].id' | sed 's/\"//g') )
for i in "${!resources[@]}"; do
    echo "resource ${resources[$i]}:" >> $logfile
    az monitor diagnostic-settings list --resource ${resources[$i]} >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "LEVEL 1 SECTION 6: Networking" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

audit_requirement "6.1, 6.2, 6.6 - Ensure that RDP/SSH access is restricted from the Internet, Ensure that UDP Services are restricted from the Internet" "az network nsg list --query '[*].[name,securityRules]'"

audit_requirement "6.5 - Ensure that Network Watcher is 'Enabled'" "az network watcher list"

echo $section_header >> $logfile
echo "LEVEL 1 SECTION 7: Virtual Machines" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

echo $section_header >> $logfile
echo "7.4 - Ensure that only approved extensions are installed" >> $logfile
vms=( $(az vm list --query '[*].[name,resourceGroup]' | grep '"' | awk '{print $1}' | sed 's/[\"|,]//g') )
len_vms=${#vms[@]}
if [[ ${len_vms} -eq 0 ]]; then
    echo "no vms found" >> $logfile
else
    num_vms=$(expr ${len_vms} / 2)
    last_index=$(expr ${len_vms} - 1)
    echo "found ${num_vms} vms" >> $logfile
    for i in $(seq 0 $last_index); do
        if !((i % 2)); then
            rgroup_index=$(expr $i + 1)
            resource_group=$(echo ${vms[$rgroup_index]})
            vm=$(echo ${vms[$i]})
            echo "vm: ${vm}, resource group: ${resource_group}" >> $logfile
            az vm extension list --vm-name ${vm} --resource-group ${resource_group} --query '[*].name' >> $logfile 2>&1
        fi
    done
fi

echo $section_header >> $logfile
echo "LEVEL 1 SECTION 8: Other Security Concerns" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

echo $section_header >> $logfile
echo "8.1 - Ensure that the expiration date is set on all keys" >> $logfile
keyvault_names=( $(az keyvault list --query '[*].name' | grep '"' | awk '{print $1}' | sed 's/[\"|,]//g') )
for i in "${!keyvault_names[@]}"; do
    echo "key vault ${keyvault_names[$i]}:" >> $logfile
    az keyvault key list --vault-name ${keyvault_names[$i]} --query '[*].[{"kid":kid},{"enabled":attributes.enabled},{"expires":attributes.expires}]' >> $logfile 2>&1 
done

echo $section_header >> $logfile
echo "8.2 - Ensure that the expiration date is set on all Secrets" >> $logfile
for i in "${!keyvault_names[@]}"; do
    echo "key vault ${keyvault_names[$i]}:" >> $logfile
    az keyvault secret list --vault-name ${keyvault_names[$i]} --query '[*].[{"id":id},{"enabled":attributes.enabled},{"expires":attributes.expires}]' >> $logfile 2>&1 
done

echo $section_header >> $logfile
echo "8.4 - Ensure the key vault is recoverable" >> $logfile
for i in "${!keyvaults[@]}"; do
    echo "key vault ${keyvaults[$i]}:" >> $logfile
    az resource show --id ${keyvaults[$i]} >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "LEVEL 2 SECTION 2: Security Center" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

audit_requirement "2.1 - Ensure that Azure Defender is set to On for Servers" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/pricings?api-version=2018-06-01' | jq '.|.value[] | select(.name==\"VirtualMachines\")'|jq '.properties.pricingTier'"

audit_requirement "2.2 - Ensure that Azure Defender is set to On for App Service" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/pricings?api-version=2018-06-01' | jq '.|.value[] | select(.name==\"AppServices\")'|jq '.properties.pricingTier'"

audit_requirement "2.3 - Ensure that Azure Defender is set to On for Azure SQL database servers" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/pricings?api-version=2018-06-01' | jq '.|.value[] | select(.name==\"SQLServers\")'|jq '.properties.pricingTier'"

audit_requirement "2.4 - Ensure that Azure Defender is set to On for SQL servers on machines" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/pricings?api-version=2018-06-01' | jq '.|.value[] | select(.name==\"SQLserverVirtualMachines\")'|jq '.properties.pricingTier'"

audit_requirement "2.5 - Ensure that Azure Defender is set to On for Storage" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/pricings?api-version=2018-06-01' | jq '.|.value[] | select(.name==\"StorageAccounts\")'|jq '.properties.pricingTier'"

audit_requirement "2.6 - Ensure that Azure Defender is set to On for Kubernetes" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/pricings?api-version=2018-06-01' | jq '.|.value[] | select(.name==\"KubernetesService\")'|jq '.properties.pricingTier'"

audit_requirement "2.7 - Ensure that Azure Defender is set to On for Container Registries" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/pricings?api-version=2018-06-01' | jq '.|.value[] | select(.name==\"ContainerRegistry\")'|jq '.properties.pricingTier'"

audit_requirement "2.8 - Ensure that Azure Defender is set to On for Key Vault" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/pricings?api-version=2018-06-01' | jq '.|.value[] | select(.name==\"KeyVaults\")'|jq '.properties.pricingTier'"

audit_requirement "2.9 - Ensure that Windows Defender ATP (WDATP) integration with Security Center is selected" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/settings?api-version=2019-01-01' | jq '.|.value[] | select(.name==\"WDATP\")'|jq '.properties.enabled'"

audit_requirement "2.10 - Ensure that Microsoft Cloud App Security (MCAS) integration with Security Center is selected" "az account get-access-token --query \"{subscription:subscription,accessToken:accessToken}\" --out tsv | xargs -L1 bash -c 'curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" https://management.azure.com/subscriptions/\$0/providers/Microsoft.Security/settings?api-version=2019-01-01' | jq '.|.value[] | select(.name==\"MCAS\")'|jq '.properties.enabled'"

echo $section_header >> $logfile
echo "LEVEL 2 SECTION 3: Storage Accounts" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

audit_requirement "3.6, 3.7 - Ensure default network access rule for Storage Accounts is set to deny\
Ensure 'Trusted Microsoft Services' is enabled for Storage Account access" "az storage account list --query '[*].networkRuleSet'"

echo $section_header >> $logfile
echo "3.10 - Ensure Storage logging is enabled for Blob service for read, write, and delete requests" >> $logfile
echo "3.11 - Ensure Storage logging is enabled for Table service for read, write, and delete requests" >> $logfile
storage_accounts=( $(az storage account list --query '[*].name' | grep '"' | awk '{print $1}' | sed 's/[\"|,]//g'))
for i in "${!storage_accounts[@]}"; do
    echo "storage account ${storage_accounts[$i]}:" >> $logfile
    az storage logging show --services b --account-name ${storage_accounts[$i]} >> $logfile 2>&1
    az storage logging show --services t --account-name ${storage_accounts[$i]} >> $logfile 2>&1
done

echo $section_header >> $logfile
echo "LEVEL 2 SECTION 4: Database Services" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

echo $section_header >> $logfile
echo "4.5 - Ensure SQL server's TDE protector is encrypted with Customer-managed key" >> $logfile
sql_servers=( $(az sql server list --query '[*].[name,resourceGroup]' | grep '"' | awk '{print $1}' | sed 's/[\"|,]//g') )
len_sql_servers=${#sql_servers[@]}
if [[ ${len_sql_servers} -eq 0 ]]; then
    echo "no sql servers found" >> $logfile
else
    num_servers=$(expr ${len_sql_servers} / 2)
    last_index=$(expr ${num_servers} - 1)
    echo "found ${num_servers} SQL servers" >> $logfile
    for i in $(seq 0 $last_index); do
        if ! ((i % 2)); then
            rgroup_index=$(expr $i + 1)
            resource_group=$(echo ${sql_servers[$rgroup_index]})
            server=$(echo ${sql_servers[$i]})
            echo "server: ${server}, resource group: ${resource_group}" >> $logfile
            az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c "curl -s -X GET -H \"Authorization: Bearer \$1\" -H \"Content-Type: application/json\" GET https://management.azure.com/subscriptions/\$0/resourceGroups/$resource_group/providers/Microsoft.Sql/servers/$server/encryptionProtector?api-version=2015-05-01-preview" >> $logfile 2>&1
        fi
    done
fi

echo $section_header >> $logfile
echo "LEVEL 2 SECTION 7: Virtual Machines" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

echo "7.7 - Ensure that VHDs are encrypted" >> $logfile
len_vms=${#vms[@]}
if [[ ${len_vms} -eq 0 ]]; then
    echo "no vms found" >> $logfile
else
    num_vms=$(expr ${len_vms} / 2)
    last_index=$(expr ${len_vms} - 1)
    echo "found ${num_vms} vms" >> $logfile
    for i in $(seq 0 $last_index); do
        if !((i % 2)); then
            rgroup_index=$(expr $i + 1)
            resource_group=$(echo ${vms[$rgroup_index]})
            vm=$(echo ${vms[$i]})
            echo "vm: ${vm}, resource group: ${resource_group}" >> $logfile
            az vm encryption show --name ${vm} --resource-group ${resource_group} >> $logfile 2>&1
        fi
    done
fi

echo $section_header >> $logfile
echo "LEVEL 2 SECTION 9: AppService" | tee -a $logfile
echo $section_header >> $logfile
echo "" >> $logfile

echo "9.1 - Ensure App Service Authentication is set on Azure App Service" >> $logfile
echo "9.4 - Ensure the web app has 'Client Certificates (Incoming client certificates)' set to 'On'" >> $logfile
webapps=( $(az webapp list --query '[*].[name,resourceGroup]' | grep '"' | awk '{print $1}' | sed 's/[\"|,]//g') )
len_webapps=${#webapps[@]}
if [[ ${len_webapps} -eq 0 ]]; then
    echo "no webapps found" >> $logfile
else
    num_webapps=$(expr ${len_webapps} / 2)
    last_index=$(expr ${num_webapps} - 1)
    echo "found ${num_webapps} web apps" >> $logfile
    for i in $(seq 0 $last_index); do
        if ! ((i % 2)); then
            rgroup_index=$(expr $i + 1)
            resource_group=$(echo ${webapps[$rgroup_index]})
            webapp=$(echo ${webapps[$i]})
            echo "webapp: ${webapp}, resource group: ${resource_group}" >> $logfile
            az webapp auth show --resource-group ${resource_group} --name ${webapp} --query enabled >> $logfile 2>&1
            az webapp show --resource-group ${resource_group} --name ${webapp} --query clientCertEnabled >> $logfile 2>&1
        fi
    done
fi

echo "Script complete" | tee -a $logfile

exit 0