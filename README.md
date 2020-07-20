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

### Resilient Username
The username of the Resilient user you want the integration to authenticate as.

### Password
The password for the provided username you want the integration to authenticate as.

### Resilient Org Id
Your Resilient Org ID. You can find your resilient org id by navigating to Administrator settings then clicking on the Organization tab. Please note you must be a Resilient Administrator in order to access your Org Id.

### Types to Search

The types of data that should be searched.  Options include "Incidents", "Notes", "Artifacts", and "Tasks".  

### Ignored List

Comma separated list of entities that you never want looked up in Resilient. 

### Ignored Domain Regex

Domains that match the given regex will not be looked up.

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
