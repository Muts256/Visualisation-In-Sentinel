

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
https://github.com/joshmadakor1/lognpacific-public/blob/main/cyber-range/sentinel/Azure-Resource-Creation.json
````

```
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "// Only works for IPv4 Addresses\nlet GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet AzureActivityRecords = AzureActivity\n| where not(Caller matches regex @\"^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$\")\n| where CallerIpAddress matches regex @\"\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b\"\n| where OperationNameValue endswith \"WRITE\" and (ActivityStatusValue == \"Success\" or ActivityStatusValue == \"Succeeded\")\n| summarize ResouceCreationCount = count() by Caller, CallerIpAddress;\nAzureActivityRecords\n| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)\n| project Caller, \n          CallerPrefix = split(Caller, \"@\")[0],  // Splits Caller UPN and takes the part before @\n          CallerIpAddress, \n          ResouceCreationCount, \n          Country = countryname, \n          Latitude = latitude, \n          Longitude = longitude, \n          friendly_label = strcat(split(Caller, \"@\")[0], \" - \", cityname, \", \", countryname)\n",
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
      "sizeSettings": "ResouceCreationCount",
      "sizeAggregation": "Sum",
      "labelSettings": "friendly_label",
      "legendMetric": "ResouceCreationCount",
      "legendAggregation": "Sum",
      "itemColorSettings": {
        "nodeColorField": "ResouceCreationCount",
        "colorAggregation": "Sum",
        "type": "heatmap",
        "heatmapPalette": "greenRed"
      }
    }
  },
  "name": "query - 2"
}

```

Query 

```
// Only works for IPv4 Addresses
let GeoIPDB_FULL = _GetWatchlist("geoip");
let AzureActivityRecords = AzureActivity
| where not(Caller matches regex @"^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$")
| where CallerIpAddress matches regex @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
| where OperationNameValue endswith "WRITE" and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")
| summarize ResouceCreationCount = count() by Caller, CallerIpAddress;
AzureActivityRecords
| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)
| project Caller, 
          CallerPrefix = split(Caller, "@")[0],  // Splits Caller UPN and takes the part before @
          CallerIpAddress, 
          ResouceCreationCount, 
          Country = countryname, 
          Latitude = latitude, 
          Longitude = longitude, 
          friendly_label = strcat(split(Caller, "@")[0], " - ", cityname, ", ", countryname)

```

![image alt](Vi15)
