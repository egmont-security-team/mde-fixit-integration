# MDE FixIt Integration

A Azure Function that uses data from Microsoft Defender and FixIt to automate certain tasks descried in the [Automation](#automation) sections.

## Automations

- [Inactive Devices](#inactive-devices): Adds `ZZZ` tags to duplicate devices in Defender Portal.

- [Cleanup FixIt Tags](#cleanup-fixit-tags): Removes FixIt tags from completed FixIt requests.

- [Critical Exposure Requests](#critical-exposure-requests): Create a FixIt request for devices hit by a `critical` exposure CVE.

- [High Exposure Requests](#high-exposure-requests): Create a FixIt request for devices hit by a `high` exposure CVE after 25 days.

### Detailed description

#### Inactive Devices

Checks if the device name is found multiple times in the Defender Portal. If the device does exists multiple times, we make sure it is inactive and then add the `ZZZ` tag to the devices.

#### Cleanup FixIt tags

This checks all devices for FixIt tags and then checks if the referenced tag is closed in the FixIt portal. If the FixIt request referenced by the tag on the device is closed, the tag is removed from the device.

#### Critical Exposure FixIt Requests

This checks for devices hit by vulnerabilities with a severity of `critical`. For each device hit by a vulnerability, a FixIt ticket is created. This ticket contains all recomended application updates for the device.

If a vulnerability has more vulnerable devices than a set [device threshold](#environment-variables[1]), a multiticket will instead be created and sent to another team.

#### High Exposure Requests

To be implemented.

## Configuration

### Environment variables

- Set the environment variable `KEY_VAULT_NAME` to change what key vault will be used to load secrets.
- Set the environment variable `CVE_DEVICE_THRESHOLD` to change how many devices under 1 vulnerability, to count it as a multi vulnerability.

### Access needed

**The access for FixIt:** You need an API token that can read and write/create requests.

**The access for Microsoft Defender:** You need the scope variables below:
- Machine.ReadWrite.All
- Vulnerability.Read.All
- SecurityRecommendation.Read.All
- AdvancedQuery.Read.All
