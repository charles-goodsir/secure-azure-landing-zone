# Secure Azure Landing Zone

I defined a small Azure environment in Terraform and deploy it through an Azure DevOps pipeline. The pipeline checks and scans my code, then holds the deployment until I approve it.

> I built a Terraform-defined Azure environment that deploys through Azure Pipelines. Security
> scanning caught six misconfigurations in my own Key Vault and storage configs and blocked each
> deployment. I fixed four, accepted two with written reasons, and documented the before and
> after, applying the fix-and-verify habit from my AppSec homelab to infrastructure.

![Full pipeline passing](screenshots/SALZ12.webp)

## What this demonstrates

- **Infrastructure as Code:** Terraform defines each Azure resource. I don't create anything by clicking in the Portal.
- **Shift-left security:** Trivy runs before `plan`. An insecure config fails the pipeline while it's still code.
- **Supply-chain checks:** the pipeline downloads a pinned Trivy release and verifies its SHA-256 checksum before running it. A committed `.terraform.lock.hcl` pins the azurerm provider version and hashes, and each `terraform init` runs with `-lockfile=readonly`, so a provider that doesn't match fails the pipeline.
- **Change control:** the Plan stage publishes the saved plan as an artifact. A manual approval gate sits in front of `apply`, and Apply runs the plan I approved without re-planning.
- **No stored secrets:** the pipeline signs in to Azure with workload identity federation (OIDC), so I have no client secret to leak.

## Architecture

```mermaid
flowchart LR
    GH[GitHub repo<br/>push to main] --> V

    subgraph ADO[Azure DevOps pipeline]
        V[1. Validate<br/>fmt · init · validate] --> S[2. Security Scan<br/>Trivy]
        S --> P[3. Plan<br/>tfplan artifact]
        P --> A{4. Manual<br/>approval}
        A --> AP[5. Apply<br/>saved plan]
    end

    AP -- OIDC service connection --> RG

    subgraph Azure
        TS[(rg-tfstate<br/>remote state)]
        subgraph RG[salz-rg]
            VNET[VNet 10.0.0.0/16] --> SN[Subnet 10.0.1.0/24]
            NSG[NSG<br/>deny by default] --- SN
            ST[Storage account<br/>TLS 1.2 · HTTPS only · no public access · network rules deny]
            KV[Key Vault<br/>RBAC · purge protection · network ACL deny]
        end
    end

    P -. reads/writes state .-> TS
    AP -. reads/writes state .-> TS
```

## Resources deployed

| Resource | Security settings |
|---|---|
| Resource group `salz-rg` | Holds the resources below. It sits apart from the state storage |
| Virtual network + subnet | Private address space `10.0.0.0/16`, subnet `10.0.1.0/24` |
| Network security group | No allow rules, so Azure's implicit deny applies. Attached to the subnet |
| Storage account | Minimum TLS 1.2, HTTPS only, public network access disabled, network rules default `Deny`, infrastructure encryption |
| Key Vault | RBAC authorization, purge protection, 7-day soft delete, network ACL default `Deny` |

Terraform keeps its state in a separate resource group, `rg-tfstate`. I created that storage once by hand with `az cli`, since Terraform needs somewhere to write state before it can manage anything. The separation also protects the state: running `terraform destroy` on the landing zone can't delete it.

## The pipeline

[`azure-pipelines.yml`](../azure-pipelines.yml) defines the pipeline. Each push to `main` starts a run.

### 1. Validate
The stage installs Terraform 1.9.8 and runs `terraform fmt -check`, `terraform init -backend=false` and `terraform validate`. It catches mistakes in seconds and needs no Azure credentials.

![Validate stage passing](screenshots/SALZ5.webp)

### 2. Security Scan
Trivy v0.74.0 scans `terraform/` with `trivy config --exit-code 1`. Trivy exits 0 by default even when it finds problems, so `--exit-code 1` is what makes a single finding fail the pipeline.

The stage downloads Trivy straight from its GitHub release and checks it against the release's SHA-256 checksum file. `set -euo pipefail` at the top of the script stops the step on a mismatch, before the binary runs.

I started with tfsec and switched to Trivy after tfsec's own logs announced it was moving into Trivy. [misconfiguration-findings.md](misconfiguration-findings.md) covers what each scanner caught.

![Validate and Security Scan passing](screenshots/SALZ7.webp)

### 3. Plan
The stage signs in through the service connection, connects to the remote backend and runs `terraform plan -out=tfplan`. It publishes the plan file as a pipeline artifact for Apply to use.

![Plan stage publishing the tfplan artifact](screenshots/SALZ9.webp)

### 4. Manual approval
I made Apply a `deployment` job that targets an ADO environment called `production`. That environment has an approval check, so the pipeline pauses until I approve.

![Apply stage waiting for approval on the production environment](screenshots/SALZ14.webp)

### 5. Apply
The stage checks out the repo, downloads the `tfplan` artifact and runs `terraform apply` against it.

![Apply stage YAML](screenshots/SALZ10.webp)

The activity log for `salz-rg` shows the deployment. The `'audit'` entries come from Azure Policy checking each new resource:

![salz-rg activity log](screenshots/SALZ13.webp)

## Problems I hit and how I fixed them

Most stages failed at least once before they worked.

| Problem | Cause | Fix |
|---|---|---|
| Install step hung until timeout | `unzip` waited at an "overwrite?" prompt, and a hosted agent has no stdin to answer it | `unzip -o` overwrites without asking |
| `Not found workingDirectory: .../terraform` | My install script ran `rm -rf terraform` at the repo root. The binary and my source folder shared the name `terraform`, so the script deleted my code | I moved the download and install into a separate `tf-install/` directory |
| `bashtfsec: command not found` | I lost a line break, which merged two shell commands into one | I restored the newline. In a YAML `script: \|` block, each line runs as its own shell command |
| `Authenticating using the Azure CLI is only supported as a User` | `AzureCLI@2` signs in the `az` CLI, but Terraform's azurerm backend handles its own sign-in and rejects CLI sign-in for a service principal | I set `addSpnToEnvironment: true` and exported `ARM_CLIENT_ID`, `ARM_TENANT_ID`, `ARM_SUBSCRIPTION_ID`, `ARM_USE_OIDC` and `ARM_OIDC_TOKEN` |
| Apply found no Terraform config | A `deployment` job skips the repo checkout that a regular `job` does | I added `- checkout: self`, ran from `$(Build.SourcesDirectory)/terraform` and pointed `apply` at `$(Pipeline.Workspace)/tfplan/tfplan` |
| The Trivy checksum check blocked nothing | Bash keeps running after a failed command, so a tampered download would print `FAILED` and then install and run anyway | I added `set -euo pipefail` as the script's first line |
| `StorageAccountAlreadyTaken` during Apply | Enabling infrastructure encryption forces a replace. Terraform deleted the account and asked for the same globally unique name 6 seconds later, before Azure had released it | The account held no data, so I renamed it and ran a fresh plan. On a real account I'd plan this change as a migration |

The first problem, with the install step stuck on the prompt:

![Install step hanging on unzip](screenshots/SALZ1.webp)

The same step after the fix:

![Install step succeeding](screenshots/SALZ2.webp)

## Known shortcuts

I left these in on purpose:

- **Two accepted Trivy findings:** GRS replication and storage analytics logging. [misconfiguration-findings.md](misconfiguration-findings.md) gives the reason for each.
- **Checksums from the same source:** the Trivy checksum file comes from the same GitHub release as the binary. It catches a corrupted or swapped download, but an attacker who controls the release could replace both files. Verifying Trivy's cosign signature would close that gap.
- **Unverified Terraform downloads:** the Terraform installs are pinned to 1.9.8 but skip checksum verification.
- **Hardcoded values:** I wrote names and the region straight into `main.tf` instead of using variables.
- **Direct commits to `main`:** the pipeline has no pull-request validation or branch protection yet.
- **No private endpoints:** with public access disabled and no private endpoint, only Azure's trusted services can reach the storage account and Key Vault.
