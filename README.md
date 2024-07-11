# MDE FixIt Integration

A Azure Function that uses data from Microsoft Defender and FixIt to automate certain tasks descried in the [Automation](#automation) sections.

## Automations

- [Cleanup FixIt Tags](#ddc2-cleanup-fixit-tags): Removes FixIt tags from devices if the FixIt requests is completed.

- [Inactive Devices](#ddc3-inactive-devices): Adds `ZZZ` tags to duplicate devices in the Defender Portal.

- [Critical Exposure Tickets](#cve-critical-exposure-tickets): Create a FixIt request for devices hit by a `critical` CVEs.

### Detailed description

#### DDC2: Cleanup FixIt tags

Checks if the device name is found multiple times in the Defender Portal. If the device does exists multiple times, we make sure it is inactive and then add the `ZZZ` tag to the devices.

This checks all devices for FixIt tags and then checks if the ticket referenced by the tag is completed. If the FixIt request is completed, the tag is removed from the device.

This checks all devices for FixIt tags and then checks if the referenced tag is closed in the FixIt portal. If the FixIt request referenced by the tag on the device is closed, the tag is removed from the device.

#### Critical Exposure FixIt Requests

This checks for devices hit by vulnerabilities with a severity of `critical`. For each device hit by a vulnerability, a FixIt ticket is created. This ticket contains all recomended application updates for the device.

If a vulnerability has more vulnerable devices than a set [device threshold](#environment-variables[1]), a multiticket will instead be created for all the devices to be handled as one problem.

## Configuration

### Environment variables

- Set the environment variable `KEY_VAULT_NAME` to change what key vault will be used to load secrets.
- Set the environment variable `CVE_DEVICE_THRESHOLD` to change how many devices under 1 vulnerability to create a multi ticket.

### Access needed

**The access for FixIt:** You need an API token that can read and write/create requests.

**The access for Microsoft Defender:** You need the scopes below:

- Machine.ReadWrite.All
- Vulnerability.Read.All
- SecurityRecommendation.Read.All
- AdvancedQuery.Read.All
