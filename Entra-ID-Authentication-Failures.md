### Introduction

These Entra ID authentication failure maps and visualizations provide a geographic and analytical view of failed sign-in activity, helping to identify suspicious access patterns such as anomalous locations, brute-force attempts, and credential abuse. By visualizing authentication failures across regions and time, security teams can quickly detect abnormal behavior, prioritize investigations, and strengthen identity protection strategies.

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
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "SigninLogs\n| where ResultType != 0 and Identity !contains \"-\"\n| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails[\"geoCoordinates\"][\"latitude\"]), Longitude = tostring(LocationDetails[\"geoCoordinates\"][\"longitude\"]), City = tostring(LocationDetails[\"city\"]), Country = tostring(LocationDetails[\"countryOrRegion\"])\n| order by LoginCount desc\n| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, \" - \", City, \", \", Country)\n",
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
      "numberOfMetrics": 0,
      "legendAggregation": "Count",
      "itemColorSettings": {
        "nodeColorField": "LoginCount",
        "colorAggregation": "Count",
        "type": "heatmap",
        "heatmapPalette": "greenRed"
      }
    }
  },
  "name": "query - 2"
}
```
### Map Visual

![image alt](https://github.com/Muts256/SNC-Public/blob/d2ce8715101cd8bd956d74a6ec1b7bdd42a10754/Images/Visual/Vi11.png)


Query

```
SigninLogs
| where ResultType != 0 and Identity !contains "-"
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| order by LoginCount desc
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)

```

### Query Explanation


---

#### 1. `SigninLogs`

Selects the **Entra ID sign-in log table**, which records all authentication attempts and includes:

- User identity
- Authentication result codes
- Source IP address
- Geolocation metadata

---

#### 2. `| where ResultType != 0 and Identity !contains "-"`

Filters the dataset to include:

- **Failed sign-in attempts**  
  Any `ResultType` value other than `0` represents an authentication failure.

- **Non-hyphenated identities**  
  The condition `Identity !contains "-"` helps exclude service accounts, managed identities, and system-generated accounts, narrowing the focus to **human user accounts**.

This filtering is useful when investigating **brute-force, password spraying, or credential-stuffing activity**.

---

#### 3. `| summarize LoginCount = count() by ...`

Aggregates failed sign-in events to calculate the **number of failed authentication attempts** for each unique combination of:

- **Identity** – the user account targeted
- **Latitude / Longitude** – geographic coordinates of the originating IP address
- **City** – city derived from IP geolocation
- **Country** – country or region of the sign-in attempt

This produces a **failure frequency per user per geographic location**, which helps identify abnormal or high-risk access patterns.

---

#### 4. `| order by LoginCount desc`

Sorts the results in descending order based on `LoginCount`, highlighting identities and locations with the **highest volume of failed authentication attempts**.

---

#### 5. `| project ...`

Selects and formats the final output fields for reporting and visualization:

- `Identity`
- `Latitude`
- `Longitude`
- `City`
- `Country`
- `LoginCount`

Additionally, a human-readable field named `friendly_label` is created using:

```kql
strcat(Identity, " - ", City, ", ", Country)
```

![iamge alt](https://github.com/Muts256/SNC-Public/blob/d2ce8715101cd8bd956d74a6ec1b7bdd42a10754/Images/Visual/Vi10.png)
