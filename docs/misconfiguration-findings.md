# Misconfiguration Findings

The pipeline's tfsec scan flagged two problems in my Key Vault config. This page shows each one before and after I fixed it.

I didn't plant these findings. They came from the first Key Vault config I wrote. I had set `public_network_access_enabled = false` and assumed that locked the vault down, and tfsec disagreed.

## Summary

| # | Severity | tfsec ID | Resource | Status |
|---|---|---|---|---|
| 1 | CRITICAL | `azure-keyvault-specify-network-acl` | `azurerm_key_vault.main` | Fixed |
| 2 | MEDIUM | `azure-keyvault-no-purge` | `azurerm_key_vault.main` | Fixed |

## Before

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

## Finding 1: No network ACL (CRITICAL)

**Risk:** the Key Vault holds secrets, keys and certificates. My config relied on the public-access flag alone and set no default network rule. If I or someone else re-enabled public access to debug something, no other control would block traffic. A secrets vault needs a stated deny rule.

**Fix:**

```hcl
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
```

`default_action = "Deny"` blocks traffic I haven't allowed. `bypass = "AzureServices"` lets trusted Azure platform services through, since some Azure integrations break without it. The rule mirrors the deny-by-default NSG on the subnet.

## Finding 2: Soft-delete retention not set (MEDIUM)

**Risk:** purge protection depends on soft delete. Soft delete keeps a deleted secret recoverable for a retention period, and purge protection stops anyone from purging it for good before that period ends. My config left the retention period to the provider default, so a reviewer reading the code couldn't see it.

**Fix:**

```hcl
  soft_delete_retention_days = 7
```

Azure allows a minimum of 7 days. For production I'd pick something closer to 90.

## After

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

## What I took from it

- The public-access flag covered one setting, and tfsec checks several. My config has to state each one.
- The gate did its job. It stopped my insecure config in CI, and I fixed the code rather than suppressing the check.
- Purge protection is permanent once enabled. After I delete this vault, Azure reserves its name for the retention period, and I can't reuse it until that ends.
