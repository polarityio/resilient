# Polarity IBM Resilient Integration
The Polarity - IBM Resilient integration searches the Resilient Incident Response Platform for incidents related to indicators on your screen.  

The integration can search across artifacts, incidents, tasks and notes.  Incident and tasks searches are  full text searches against all fields.  Artifact searches are exact match searches against the artifact's value.  Note searches are full text searches against the content of the note.

If a result is found, the integration will display information about the related incident.  Incidents are deduplicated so that an incident is only shown a single time even if it has multiple matches.

To learn more about IBM Resilient, please visit the [official website](https://www.ibm.com/us-en/marketplace/resilient-incident-response-platform).

> Note that the Resilient API and search does not return results for IP addresses if the IP is only found in the description field of an incident.  As a result, when searching incidents, the integration is unable to find results for IP addresses contained only within the description field.

| ![image](./assets/overlay.gif) |
|---|
|*Resilient Search Example*|

## Resilient Integration Options

### Resilient URL
Your URL used to access Resilient.

### Resilient API Key ID

Your Resilient API Key ID. You must authenticate with either an "API Key ID" and "API Key Secret", or a "username" and "password", but not both.

If authenticating with an API Key, your API key must have the following permissions:

* Incidents -> Read
* Edit Incidents -> Notes
* Read Tasks

### Resilient API Key Secret

Your Resilient API Key Secret token value. You must authenticate with either an "API Key ID" and "API Key Secret", or a "username" and "password", but not both.

### Resilient Username
The username of the Resilient user you want the integration to authenticate as.

### Password
The password for the provided username you want the integration to authenticate as.

### Resilient Org Id
Your Resilient Org ID. You can find your resilient org id by navigating to Administrator settings then clicking on the Organization tab. Please note you must be a Resilient Administrator in order to access your Org Id.

### Workspaces to Search
Comma delimited list of workspaces to search. If left blank, all workspaces accessible to the provided API key or user will be searched. Workspace names are case- sensitive. This option should be set to "Only admins can view and edit"

### Types to Search

The types of data that should be searched.  Options include "Incidents", "Notes", "Artifacts", and "Tasks".

### Days to Search

The number of days back to search. For example, if set to 365, the integration will limit results to incidents created in the last 365 days. Defaults to 365 days.

### Ignored List

Comma separated list of entities that you never want looked up in Resilient. 

### Ignored Domain Regex

Domains that match the given regex will not be looked up.

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
