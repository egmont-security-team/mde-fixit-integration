# MDE FixIt Integration

A Azure Function that uses data from Microsoft Defender and FixIt to automate certain tasks described in the [Automations](#automations) sections.

## Automations

- [Cleanup FixIt Tags](#ddc2-cleanup-fixit-tags): Removes FixIt tags from devices if the FixIt requests is completed.

- [Inactive Devices](#ddc3-inactive-devices): Adds `ZZZ` tags to duplicate devices in the Defender Portal.

- [Critical Exposure Tickets](#cve-critical-exposed-devices): Create a FixIt request for devices hit by `critical` CVEs.

### Detailed description

#### DDC2: Cleanup FixIt tags

This checks all devices for FixIt tags and then checks if the ticket referenced by the tag is completed. If the FixIt request is completed, the tag is removed from the device.

This checks all devices for FixIt tags and then checks if the referenced tag is closed in the FixIt portal. If the FixIt request referenced by the tag on the device is closed, the tag is removed from the device.

#### DDC3: Inactive Devices

Checks if the device name is found multiple times in the Defender Portal. If the device does exists multiple times, we make sure it is inactive and then add the `ZZZ` tag to the devices.

#### CVE: Critical Exposed Devices

This checks for devices hit by vulnerabilities with a severity of `critical`. For each device hit by a vulnerability, a FixIt ticket is created. This ticket contains all recommended application updates for the device.

If no application updates is found, the ticket is sent to the security team instead of service desk.

If a vulnerability has more vulnerable devices than a set [device threshold](#environment-variables), a multiticket will instead be created for all the devices to be handled as one vulnerability. This will also send the ticket the EUX instead.

### Skipping Automations

If a device should not be included in a automation, you can give specific tags in the defender portal. These tags are the following:

- `SKIP-DDC2`: Skip the [DDC2](#ddc2-cleanup-fixit-tags) automation.
- `SKIP-DDC3`: Skip the [DDC3](#ddc3-inactive-devices) automation.
- `SKIP-CVE`: Skip the [CVE](#cve-critical-exposed-devices) automation.
- `SKIP-CVE[CVE-XXXX-XXXXXXX]`: Skip a specefic CVE in the [CVE](#cve-critical-exposed-devices) automation.

## Configuration

### Environment variables

- Set the environment variable `KEY_VAULT_NAME` to change what key vault will be used to load secrets.
- Set the environment variable `CVE_PC_THRESHOLD` to change how many pc under 1 vulnerability to create a multi ticket.
- Set the environment variable `CVE_SERVER_THRESHOLD` to change how many servers under 1 vulnerability to create a multi ticket.

### Secrets

#### MDE

- `MDE_TENANT`: Set this to change what tenant the MDE environment is in.
- `MDE_CLIENT_ID`: The client id of the enterprise app for defender.
- `MDE_SECRET_VALUE`: The secret value of the enterprise app for defender.

#### FixIt

- `FIXIT_4ME_BASE_URL`: The [base URL](https://developer.4me.com/v1/) of the FixIt 4me API (also called service URL)
- `FIXIT_4ME_ACCOUNT`: The FxiIt 4me account which we check.
- `FIXIT_4ME_API_KEY`: The API key with the right permission from the [Access needed](#access-needed) section.
- `FIXIT_SINGLE_TEMPLATE_ID`: The template ID of the single vulnerable device template.
- `FIXIT_MULTI_TEMPLATE_ID`: The template ID of the a multiple vulnerable devices template.
- `FIXIT_SERVICE_INSTANCE_ID`: The service instance of where the requests will be created.
- `FIXIT_SD_TEAM_ID`: The team ID of the service desk team.
- `FIXIT_MW_TEAM_ID`: The team ID of the modern workplace team.
- `FIXIT_SEC_TEAM_ID`: The team ID of the security team.
- `FIXIT_CAD_TEAM_ID`: The team ID of the cloud advisory and delivery team.

### Access needed

**The access for FixIt:** You need an API token that can read and write/create requests.

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
