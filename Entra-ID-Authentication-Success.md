### Introduction

This project demonstrates a security-focused visualization of Microsoft Entra ID authentication successes mapped by the originating IP address and geographic location. The goal is to provide high-level visibility into identity sign-in activity to support baseline establishment, anomaly detection.

By visualizing where successful authentications originate globally, security teams can quickly identify unexpected access patterns, assess geographic risk, and improve situational awareness around identity usage. This approach reflects common practices in SOC and cloud security operations, using Entra ID sign-in logs and KQL-based analysis to turn raw authentication data into actionable insight.

### Setup

Log into the Azure Portal
Go to Sentinel → Threat Management → Workbooks → Add a Workbook
Remove the default placeholders by clicking on the dots at the bottom right-hand corner and select remove

![image alt](https://github.com/Muts256/SNC-Public/blob/c092832b5026a13fbd916681555724299bca7c94/Images/Visual/Vi1.png)


Click on Add

![image alt](https://github.com/Muts256/SNC-Public/blob/c092832b5026a13fbd916681555724299bca7c94/Images/Visual/Vi3.png)


Then click on add query

![image alt](https://github.com/Muts256/SNC-Public/blob/c092832b5026a13fbd916681555724299bca7c94/Images/Visual/Vi4.png)

Click on Advanced Editor

![image alt](https://github.com/Muts256/SNC-Public/blob/c092832b5026a13fbd916681555724299bca7c94/Images/Visual/Vi5.png)

Navigate to GitHub and copy Jason script

```
https://github.com/joshmadakor1/lognpacific-public/blob/main/cyber-range/sentinel/Directory-Login-Successes.json
```
Copy the script into the Advanced Editor

```
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "SigninLogs\n| where ResultType == 0\n| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails[\"geoCoordinates\"][\"latitude\"]), Longitude = tostring(LocationDetails[\"geoCoordinates\"][\"longitude\"]), City = tostring(LocationDetails[\"city\"]), Country = tostring(LocationDetails[\"countryOrRegion\"])\n| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, \" - \", City, \", \", Country)",
    "size": 3,
    "timeContext": {
      "durationMs": 2592000000
    },
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "map",
    "mapSettings": {
      "locInfo": "LatLong",
      "latitude": "Latitude",
      "longitude": "Longitude",
      "sizeSettings": "LoginCount",
      "sizeAggregation": "Sum",
      "labelSettings": "friendly_label",
      "legendMetric": "LoginCount",
      "legendAggregation": "Sum",
      "itemColorSettings": {
        "nodeColorField": "LoginCount",
        "colorAggregation": "Sum",
        "type": "heatmap",
        "heatmapPalette": "greenRed"
      }
    }
  },
  "name": "query - 2"
}
```

After copying the script, click on done editing

![image alt](https://github.com/Muts256/SNC-Public/blob/c092832b5026a13fbd916681555724299bca7c94/Images/Visual/Vi6.png)

### Map Visual

Sentinel will render this map. The map shows the successful log-ins based on IP addresses

![image alt](https://github.com/Muts256/SNC-Public/blob/03a2d52800516bb89065a3281567d496e0d22d76/Images/Visual/Vi7.png)


To view the query that is used to generate the map. Click on edit, then click  edit again at the bottom right corner

![image alt](https://github.com/Muts256/SNC-Public/blob/c092832b5026a13fbd916681555724299bca7c94/Images/Visual/Vi8.png)

```
SigninLogs
| where ResultType == 0
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)

```

### Query Explanation

#### 1. SigninLogs

Selects the **Entra ID sign-in log table**, which records all authentication attempts, including:

- User identity
- Authentication result
- Source IP address
- Geolocation data

---

#### 2. `| where ResultType == 0`

Filters the dataset to include **only successful sign-in events**.

In Entra ID sign-in logs, a `ResultType` value of `0` indicates a successful authentication.

---

#### 3. `| summarize LoginCount = count() by ...`

Aggregates the data to calculate the number of **successful logins** for each unique combination of:

- **Identity** – the user or service account that authenticated  
- **Latitude / Longitude** – geographic coordinates of the originating IP address  
- **City** – city derived from IP geolocation  
- **Country** – country or region of the sign-in  

The result is a **login frequency per identity per geographic location**, which is useful for establishing baseline access patterns and identifying anomalies.

---

#### 4. `| project ...`

Selects and formats the final output fields for visualization and reporting:

- `Identity`
- `Latitude`
- `Longitude`
- `City`
- `Country`
- `LoginCount`

Additionally, the query creates a human-readable field named `friendly_label` using:

```kql
strcat(Identity, " - ", City, ", ", Country)
