# MDE FixIt Integration

A Azure Function that uses data from Microsoft Defender and Xurrent (4Me) to automate certain tasks described in the [Automations](#automations) sections.

## Automations

- [Cleanup ticket Tags](#ddc2-cleanup-ticket-tags): Removes ticket tags from devices if the ticket is completed.

- [Inactive Devices](#ddc3-inactive-devices): Adds `ZZZ` tags to duplicate devices in the Defender Portal.

- [Critical Exposure Tickets](#cve-critical-exposed-devices): Creates a ticket for devices hit by `critical` CVEs.

### Detailed description

#### DDC2: Cleanup ticket tags

This checks all devices for ticket tags and then checks if the ticket referenced by the tag is completed. If the ticket is completed, the tag is removed from the device.

#### DDC3: Inactive Devices

Checks if a device name is found multiple times in MDE. If the device does exists multiple times, we mark all inactive duplicates in the group with the `ZZZ` tag.

#### CVE: Critical Exposed Devices

This checks for devices hit by vulnerabilities with a severity of `critical`. For each device hit by a vulnerability, a ticket is created. This ticket contains all recommended application updates for the device.

If no application updates is found, the ticket is sent to the security team instead of service desk.

If a vulnerability has more vulnerable devices than a set [device threshold](#environment-variables), a multi ticket will instead be created for all the devices to be handled as one vulnerability. This will send the ticket to EUX or CAD instead depending of if it's a server vulnerability (or BIO for thiere devices).

### Skipping Automations

If a device should not be included in a automation, you can give specific tags in the defender portal. These tags are the following:

- `SKIP-DDC2`: Skip the [DDC2](#ddc2-cleanup-ticket-tags) automation.
- `SKIP-DDC3`: Skip the [DDC3](#ddc3-inactive-devices) automation.
- `SKIP-CVE`: Skip the [CVE](#cve-critical-exposed-devices) automation.
- `SKIP-CVE[CVE-XXXX-XXXXXXX]`: Skip a specefic CVE in the [CVE](#cve-critical-exposed-devices) automation.

## Configuration

### Environment variables

- Set the environment variable `KEY_VAULT_NAME` to change what key vault will be used to load secrets.
- Set the environment variable `CVE_THRESHOLD` to change how many devices under a vulnerability to create a multi ticket.
- Set the environment variable `CVE_SERVER_THRESHOLD` to change how many server devices under a vulnerability to create a multi ticket.

### Secrets

#### MDE

- `Azure-MDE-Tenant`: The tenant that the MDE environment is in.
- `Azure-MDE-Client-ID`: The client id of the enterprise app for defender.
- `Azure-MDE-Secret-Value`: The secret value of the enterprise app for defender.

#### Xurrent

- `Xurrent-Base-URL`: The [base URL](https://developer.4me.com/v1/) of the Xurrent (4me) API (also called service URL)
- `Xurrent-Account`: The Xurrent (4me) account used (tenant).
- `Xurrent-API-Key`: The API key with the right permission from the [Access needed](#access-needed) section.

- `CVE-Single-Template-ID`: The template ID of the single vulnerable device template.
- `CVE-Multi-Template-ID`: The template ID of the a multiple vulnerable devices template.
- `CVE-Service-Instance-ID`: The service instance of where the requests will be created.
- `CVE-BIO-Service_Instace-ID`: The service instance of where the requests will be created for BIO devices.
- `CVE-SD-Team-ID`: The team ID of the service desk team.
- `CVE-MW-Team-ID`: The team ID of the modern workplace team.
- `CVE-SOC-Team-ID`: The team ID of the security team.
- `CVE-CAD-Team-ID`: The team ID of the cloud advisory and delivery team.

### Access needed

**The access for Xurrent:** You need an API token that can read and write/create requests.

**The access for Microsoft Defender:** You need the scopes below:

- Machine.ReadWrite.All
- Vulnerability.Read.All
- SecurityRecommendation.Read.All
- AdvancedQuery.Read.All
- User.Read.All

### Known problem

In Azure, an Azure Function on a Consumption Plan is only allowed to run for 10 minutes.
This policy is enforced by Azure since a Consumption Plan does not allocated static resources.
The only way to fix this is by changing the Azure App plan to premium. This costs a lot more
money (900 DKK/Month) and are therefore not preferred right now.
