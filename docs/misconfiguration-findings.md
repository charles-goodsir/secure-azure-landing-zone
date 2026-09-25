# Misconfiguration Findings

The pipeline's security scan blocked two deployments. In round 1, tfsec flagged my Key Vault. In round 2, I switched scanners, and Trivy flagged the storage account that tfsec had passed. This page shows each finding before and after, including one I accepted and one I fixed in a way the scanner can't detect.

I didn't plant any of these. They came from configs I wrote. Both times I had set `public_network_access_enabled = false` and assumed that locked the resource down, and the scanner disagreed.

## Summary

| # | Scanner | Severity | ID | Resource | Status |
|---|---|---|---|---|---|
| 1 | tfsec | CRITICAL | `azure-keyvault-specify-network-acl` | `azurerm_key_vault.main` | Fixed |
| 2 | tfsec | MEDIUM | `azure-keyvault-no-purge` | `azurerm_key_vault.main` | Fixed |
| 3 | Trivy | CRITICAL | `AZU-0012` | `azurerm_storage_account.main` | Fixed |
| 4 | Trivy | MEDIUM | `AZU-0061` | `azurerm_storage_account.main` | Fixed |
| 5 | Trivy | MEDIUM | `AZU-0057` | `azurerm_storage_account.main` | Fixed (rule can't detect it) |
| 6 | Trivy | LOW | `AZU-0058` | `azurerm_storage_account.main` | Accepted |

## Round 1: tfsec and the Key Vault

### Before

```hcl
resource "azurerm_key_vault" "main" {
  name                          = "salz-kv-cg314214"
  location                      = azurerm_resource_group.main.location
  resource_group_name           = azurerm_resource_group.main.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  purge_protection_enabled      = true
  enable_rbac_authorization     = true
  public_network_access_enabled = false
}
```

Scanner output (pipeline run, 23 Sep 2026):

```
Result #1 CRITICAL Vault network ACL does not block access by default.
  main.tf:57-66
        ID azure-keyvault-specify-network-acl
    Impact Without a network ACL the key vault is freely accessible
Resolution Set a network ACL for the key vault

Result #2 MEDIUM Resource should have soft_delete_retention_days set between 7 and 90
                 days in order to enable purge protection.
  main.tf:57-66
        ID azure-keyvault-no-purge
    Impact Keys could be purged from the vault without protection
Resolution Enable purge protection for key vaults

  4 passed, 2 potential problem(s) detected.
##[error]Bash exited with code '1'.
```

tfsec exited with code 1 and failed the Security Scan stage. Plan and Apply never ran, and Azure received nothing.

### Finding 1: No network ACL (CRITICAL)

**Risk:** the Key Vault holds secrets, keys and certificates. My config relied on the public-access flag alone and set no default network rule. If I or someone else re-enabled public access to debug something, no other control would block traffic. A secrets vault needs a stated deny rule.

**Fix:**

```hcl
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
```

`default_action = "Deny"` blocks traffic I haven't allowed. `bypass = "AzureServices"` lets trusted Azure platform services through, since some Azure integrations break without it. The rule mirrors the deny-by-default NSG on the subnet.

### Finding 2: Soft-delete retention not set (MEDIUM)

**Risk:** purge protection depends on soft delete. Soft delete keeps a deleted secret recoverable for a retention period, and purge protection stops anyone from purging it for good before that period ends. My config left the retention period to the provider default, so a reviewer reading the code couldn't see it.

**Fix:**

```hcl
  soft_delete_retention_days = 7
```

Azure allows a minimum of 7 days. For production I'd pick something closer to 90.

### After

```hcl
resource "azurerm_key_vault" "main" {
  name                          = "salz-kv-cg314214"
  location                      = azurerm_resource_group.main.location
  resource_group_name           = azurerm_resource_group.main.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  purge_protection_enabled      = true
  soft_delete_retention_days    = 7
  enable_rbac_authorization     = true
  public_network_access_enabled = false

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}
```

With both fixes in, tfsec passed and the pipeline ran through to Apply:

![Full pipeline passing after remediation](screenshots/SALZ12.webp)

## Round 2: Trivy and the storage account

I replaced tfsec with Trivy v0.74.0, since tfsec's own logs announced it was moving into Trivy. Trivy's first scan failed on the storage account, which tfsec had passed. Trivy carries a newer rule set, and a scanner that no longer gets updates misses what the newer rules catch.

### Before

```hcl
resource "azurerm_storage_account" "main" {
  name                          = "salzstcg314214"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  min_tls_version               = "TLS1_2"
  https_traffic_only_enabled    = true
  public_network_access_enabled = false
}
```

Scanner output (pipeline run, 24 Sep 2026, trimmed):

```
Tests: 4 (SUCCESSES: 0, FAILURES: 4)
Failures: 4 (UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 0, CRITICAL: 1)

AZU-0012 (CRITICAL): No network rules defined and default action allows access.
AZU-0057 (MEDIUM): Storage account does not have logging enabled for any service.
AZU-0058 (LOW): Storage account does not use geo-redundant replication.
AZU-0061 (MEDIUM): Storage account does not have infrastructure encryption enabled.

##[error]Bash exited with code '1'.
```

### Finding 3: No network rules (CRITICAL, AZU-0012)

**Risk:** the same gap as finding 1, on a different resource. Without network rules, the storage account's default network action allows access, and the public-access flag stands as the only control.

**Fix:**

```hcl
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
```

`bypass` takes a list here and a string on the Key Vault. The two resources come from different Azure APIs, so copying the Key Vault block across fails `terraform validate`.

### Finding 4: No infrastructure encryption (MEDIUM, AZU-0061)

**Risk:** Azure encrypts storage at rest with one layer by default. Infrastructure encryption adds a second layer with a different algorithm and key, so a flaw in one layer doesn't expose the data.

**Fix:**

```hcl
  infrastructure_encryption_enabled = true
```

Azure can't switch this on for an existing account, so the plan showed a replace (`-/+`). Terraform deleted the account and tried to create the new one 6 seconds later. Azure rejected the create with `StorageAccountAlreadyTaken`, because it hadn't released the globally unique name yet. The account held no data, so I renamed it to `salzstcg314215` and ran a fresh plan. On an account holding data, I'd plan this change as a migration.

### Finding 5: No storage logging (MEDIUM, AZU-0057), fixed, rule can't detect it

**Risk:** without request logs, nobody can tell who read, wrote or deleted data in the account, or who tried and was refused.

**First decision, accept for now:** the check looks for Storage Analytics logging, which Terraform only exposes for queues. This account has no queues, so turning it on would pass the scan and log nothing useful. The real control is diagnostic settings sent to a Log Analytics workspace. I accepted the finding with an expiry date of 31 Dec 2026, so Trivy would fail the pipeline again if I never built the fix.

**The fix:** a Log Analytics workspace and a diagnostic setting on the storage account's blob service:

```hcl
resource "azurerm_monitor_diagnostic_setting" "storage_blob" {
  name                       = "blob-to-law"
  target_resource_id         = "${azurerm_storage_account.main.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageDelete"
  }
}
```

The target is the blob service, not the storage account. A diagnostic setting on the account itself only collects metrics, and no request logs, without any error. A second diagnostic setting sends the Key Vault's `AuditEvent` log to the same workspace.

**Testing the scanner:** I removed the ignore on a PR commit to see whether Trivy recognised the new logging. It still failed on AZU-0057, because the rule only checks for the legacy setting inside the storage account block. It can't see a separate diagnostic setting resource.

**Second decision, suppress without expiry:** the logging exists, and the gap is now in the rule. I restored the ignore, rewrote the reason to name the resource that provides the logging so a reviewer can check it, and removed the expiry date. An expiry would eventually fail the pipeline over a problem that's already fixed.

### Finding 6: No geo-redundant replication (LOW, AZU-0058), accepted

**Why I accepted it:** GRS copies data to a second region to survive a regional outage. That's a durability and cost decision, not a security control, and GRS costs about twice as much as LRS. This proof of concept holds no data.

### How I recorded the acceptances

I put Trivy ignore comments on the resource, with the reasons on the lines above them:

```hcl
# AZU-0058: LRS is enough for a PoC holding no data; GRS doubles the cost for durability, not security.
# AZU-0057: blob logs go to Log Analytics via azurerm_monitor_diagnostic_setting.storage_blob; this check only recognises legacy Storage Analytics logging.
#trivy:ignore:AZU-0058
#trivy:ignore:AZU-0057
resource "azurerm_storage_account" "main" {
```

A reviewer reading `main.tf` sees the decision and the reason in the same place. A bare ignore with no reason looks the same as someone hiding a problem.

Neither ignore expires now. AZU-0057 had an expiry while the fix was still to be built, and I removed it once the logging existed. AZU-0058 never had one, because LRS is a standing decision for this project.

### After

```hcl
resource "azurerm_storage_account" "main" {
  name                              = "salzstcg314215"
  resource_group_name               = azurerm_resource_group.main.name
  location                          = azurerm_resource_group.main.location
  account_tier                      = "Standard"
  account_replication_type          = "LRS"
  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true
  public_network_access_enabled     = false
  infrastructure_encryption_enabled = true

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
}
```

## What I took from it

- A single public-access flag covers one setting, and the scanners check several. My config has to state each one.
- The gate did its job twice. Each time it stopped my insecure config in CI, and I changed the code or wrote down why I accepted the risk.
- Switching scanners surfaced four findings on a resource I thought had passed. A clean scan tells me what the scanner checks, and nothing about what it skips.
- Some fixes carry a deployment cost. Infrastructure encryption forced a delete-and-recreate that failed halfway. The plan showed the `-/+` before I approved it, and that line is the one to read.
- A scanner rule can fall behind current practice. AZU-0057 only recognises legacy Storage Analytics, so proper diagnostic settings still fail it. I proved that by removing the suppression and watching the check fail, rather than assuming.
- Purge protection is permanent once enabled. After I delete this vault, Azure reserves its name for the retention period, and I can't reuse it until that ends.
