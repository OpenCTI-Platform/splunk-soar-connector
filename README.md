# OpenCTI

Publisher: Filigran  
Connector Version: 1.1.0  
Product Vendor: Filigran  
Product Name: OpenCTI  
Product Version Supported (regex): ".*"  
Minimum Product Version: 6.1.1  

Integrates OpenCTI Threat Intelligence Platform with Splunk SOAR for threat intelligence management and incident response

### Configuration Variables
The below configuration variables are required for this Connector to operate. These variables are specified when configuring a OpenCTI asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** | required | string | OpenCTI Server URL (e.g., https://opencti.example.com)
**api_token** | required | password | API Token for authentication
**ssl_verify** | optional | boolean | Verify SSL certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[convert to stix pattern](#action-convert-to-stix-pattern) - Convert Splunk SOAR artifact types to STIX pattern format  
[list indicators](#action-list-indicators) - List indicators from OpenCTI  
[create indicator](#action-create-indicator) - Create a new indicator in OpenCTI  
[get indicator](#action-get-indicator) - Get indicator details by ID  
[create intrusion set](#action-create-intrusion-set) - Create a new intrusion set  
[create malware](#action-create-malware) - Create a new malware  
[create threat actor](#action-create-threat-actor) - Create a new threat actor  
[create campaign](#action-create-campaign) - Create a new campaign  
[create vulnerability](#action-create-vulnerability) - Create a new vulnerability  
[create relationship](#action-create-relationship) - Create a relationship between two entities  
[search entities](#action-search-entities) - Search for entities in OpenCTI  
[create case incident](#action-create-case-incident) - Create a new Case-Incident in OpenCTI  
[create case rfi](#action-create-case-rfi) - Create a new Case-RFI (Request for Information) in OpenCTI  
[create case rft](#action-create-case-rft) - Create a new Case-RFT (Request for Takedown) in OpenCTI  
[create incident](#action-create-incident) - Create a new incident in OpenCTI  
[search observables](#action-search-observables) - Search for STIX cyber observables in OpenCTI  
[create observable](#action-create-observable) - Create a new STIX cyber observable in OpenCTI  
[create report](#action-create-report) - Create a new report in OpenCTI  
[create grouping](#action-create-grouping) - Create a new grouping in OpenCTI  
[add object to report](#action-add-object-to-report) - Add an object to an existing report  
[add object to grouping](#action-add-object-to-grouping) - Add an object to an existing grouping  
[create label](#action-create-label) - Create a new label in OpenCTI with predictive color generation  
[bulk create entities](#action-bulk-create-entities) - Bulk create multiple entities of the same type in OpenCTI  
[bulk add to container](#action-bulk-add-to-container) - Bulk add multiple objects to a container (report, grouping, or case)  
[add object to case incident](#action-add-object-to-case-incident) - Add an object to a case incident  
[add object to case rfi](#action-add-object-to-case-rfi) - Add an object to a case RFI (Request for Information)  
[add object to case rft](#action-add-object-to-case-rft) - Add an object to a case RFT (Request for Takedown)  
[enrich artifact](#action-enrich-artifact) - Enrich a Splunk artifact by searching for an observable in OpenCTI  
[bulk enrich artifacts](#action-bulk-enrich-artifacts) - Bulk enrich multiple Splunk artifacts by searching for observables in OpenCTI  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.message | string |  | Test connectivity passed
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'convert to stix pattern'
Convert Splunk SOAR artifact types to STIX pattern format for use with indicators

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact_type** | required | Type of artifact (e.g., 'ip', 'domain', 'hash', 'url', 'email', 'file name', etc.) | string | 
**artifact_value** | required | Value of the artifact to convert | string | 
**additional_properties** | optional | Additional properties for complex patterns (format: 'property1=value1,property2=value2') | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.artifact_type | string |  | ip
action_result.parameter.artifact_value | string |  | 192.168.1.1
action_result.parameter.additional_properties | string |  | dst_port=443
action_result.data.\*.original_type | string |  | ip
action_result.data.\*.original_value | string |  | 192.168.1.1
action_result.data.\*.stix_pattern | string | stix pattern | [ipv4-addr:value = '192.168.1.1']
action_result.data.\*.pattern_type | string |  | stix
action_result.data.\*.detected_observable_type | string |  | ipv4
action_result.summary.conversion_successful | boolean |  | True
action_result.summary.stix_pattern | string | stix pattern | [ipv4-addr:value = '192.168.1.1']
action_result.message | string |  | Successfully converted to STIX pattern
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'list indicators'
List indicators from OpenCTI

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum number of indicators to retrieve | numeric | 
**search** | optional | Search term to filter indicators | string | 
**indicator_types** | optional | Comma-separated list of indicator types to filter | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.limit | numeric |  | 50
action_result.parameter.search | string |  | malware
action_result.data.\*.id | string | opencti indicator id | indicator--abc123
action_result.data.\*.name | string |  | Malicious IP
action_result.data.\*.pattern | string |  | [ipv4-addr:value = '192.168.1.1']
action_result.data.\*.x_opencti_score | numeric |  | 75
action_result.summary.total_indicators | numeric |  | 10
action_result.message | string |  | Successfully retrieved 10 indicators
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create indicator'
Create a new indicator in OpenCTI

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the indicator | string | 
**pattern** | required | STIX pattern for the indicator | string | 
**indicator_type** | optional | Main observable type | string | 
**description** | optional | Description of the indicator | string | 
**valid_from** | optional | Valid from date (ISO 8601 format) | string | 
**valid_until** | optional | Valid until date (ISO 8601 format) | string | 
**score** | optional | Threat score (0-100) | numeric | 
**labels** | optional | Comma-separated list of labels | string | 
**marking_refs** | optional | Comma-separated list of marking definition IDs | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.name | string |  | Malicious Domain
action_result.parameter.pattern | string |  | [domain-name:value = 'evil.com']
action_result.data.\*.id | string | opencti indicator id | indicator--def456
action_result.data.\*.name | string |  | Malicious Domain
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created indicator
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'get indicator'
Get indicator details by ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_id** | required | ID of the indicator to retrieve | string | opencti indicator id

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.indicator_id | string | opencti indicator id | indicator--abc123
action_result.data.\*.id | string | opencti indicator id | indicator--abc123
action_result.data.\*.name | string |  | Malicious IP
action_result.data.\*.pattern | string |  | [ipv4-addr:value = '192.168.1.1']
action_result.summary.found | boolean |  | True
action_result.message | string |  | Successfully retrieved indicator
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create intrusion set'
Create a new intrusion set

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the intrusion set | string | 
**description** | optional | Description of the intrusion set | string | 
**first_seen** | optional | First seen date (ISO 8601 format) | string | 
**last_seen** | optional | Last seen date (ISO 8601 format) | string | 
**goals** | optional | Comma-separated list of goals | string | 
**resource_level** | optional | Resource level | string | 
**primary_motivation** | optional | Primary motivation | string | 
**secondary_motivations** | optional | Comma-separated list of secondary motivations | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.name | string |  | APT28
action_result.data.\*.id | string | opencti intrusion set id | intrusion-set--abc123
action_result.data.\*.name | string |  | APT28
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created intrusion set
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create malware'
Create a new malware

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the malware | string | 
**description** | optional | Description of the malware | string | 
**malware_types** | optional | Comma-separated list of malware types | string | 
**is_family** | optional | Whether this is a malware family | boolean | 
**architecture_execution_envs** | optional | Comma-separated list of architectures | string | 
**implementation_languages** | optional | Comma-separated list of implementation languages | string | 
**capabilities** | optional | Comma-separated list of capabilities | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.name | string |  | Emotet
action_result.data.\*.id | string | opencti malware id | malware--def456
action_result.data.\*.name | string |  | Emotet
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created malware
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create threat actor'
Create a new threat actor

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the threat actor | string | 
**description** | optional | Description of the threat actor | string | 
**threat_actor_types** | optional | Comma-separated list of threat actor types | string | 
**first_seen** | optional | First seen date (ISO 8601 format) | string | 
**last_seen** | optional | Last seen date (ISO 8601 format) | string | 
**goals** | optional | Comma-separated list of goals | string | 
**roles** | optional | Comma-separated list of roles | string | 
**sophistication** | optional | Level of sophistication | string | 
**resource_level** | optional | Resource level | string | 
**primary_motivation** | optional | Primary motivation | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.name | string |  | Lazarus Group
action_result.data.\*.id | string | opencti threat actor id | threat-actor--ghi789
action_result.data.\*.name | string |  | Lazarus Group
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created threat actor
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create campaign'
Create a new campaign

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the campaign | string | 
**description** | optional | Description of the campaign | string | 
**first_seen** | optional | First seen date (ISO 8601 format) | string | 
**last_seen** | optional | Last seen date (ISO 8601 format) | string | 
**objective** | optional | Campaign objective | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.name | string |  | Operation Aurora
action_result.data.\*.id | string | opencti campaign id | campaign--jkl012
action_result.data.\*.name | string |  | Operation Aurora
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created campaign
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create vulnerability'
Create a new vulnerability

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the vulnerability (e.g., CVE-2025-0001) | string | 
**description** | optional | Description of the vulnerability | string | 
**x_opencti_base_score** | optional | CVSS base score | numeric | 
**x_opencti_base_severity** | optional | Base severity (Low, Medium, High, Critical) | string | 
**x_opencti_attack_vector** | optional | Attack vector | string | 
**x_opencti_integrity_impact** | optional | Integrity impact | string | 
**x_opencti_availability_impact** | optional | Availability impact | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.name | string |  | CVE-2025-0001
action_result.data.\*.id | string | opencti vulnerability id | vulnerability--mno345
action_result.data.\*.name | string |  | CVE-2025-0001
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created vulnerability
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create relationship'
Create a relationship between two entities

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**relationship_type** | required | Type of relationship | string | 
**source_id** | required | Source entity ID | string | 
**target_id** | required | Target entity ID | string | 
**description** | optional | Description of the relationship | string | 
**first_seen** | optional | First seen date (ISO 8601 format) | string | 
**last_seen** | optional | Last seen date (ISO 8601 format) | string | 
**confidence** | optional | Confidence level (0-100) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.relationship_type | string |  | uses
action_result.data.\*.id | string |  | relationship--pqr678
action_result.data.\*.relationship_type | string |  | uses
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created relationship
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'search entities'
Search for entities in OpenCTI

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**search_term** | required | Search term | string | 
**entity_types** | optional | Comma-separated list of entity types to search | string | 
**limit** | optional | Maximum number of results | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.search_term | string |  | APT
action_result.data.\*.id | string |  | threat-actor--stu901
action_result.data.\*.entity_type | string |  | Threat-Actor
action_result.data.\*.name | string |  | APT28
action_result.summary.total_results | numeric |  | 5
action_result.message | string |  | Found 5 entities
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create case incident'
Create a new Case-Incident in OpenCTI

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the case | string | 
**description** | optional | Description of the case | string | 
**priority** | optional | Priority (P1, P2, P3, P4) | string | 
**severity** | optional | Severity (low, medium, high, critical) | string | 
**assignee_id** | optional | ID of the assignee | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.name | string |  | Security Breach Investigation
action_result.data.\*.id | string | opencti case id | case-incident--vwx234
action_result.data.\*.name | string |  | Security Breach Investigation
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created case incident
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create case rfi'
Create a new Case-RFI (Request for Information) in OpenCTI

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the RFI | string | 
**description** | optional | Description of the RFI | string | 
**priority** | optional | Priority (P1, P2, P3, P4) | string | 
**severity** | optional | Severity (low, medium, high, critical) | string | 
**information_types** | optional | Types of information requested | string | 
**assignee_id** | optional | ID of the assignee | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.name | string |  | Threat Intelligence Request
action_result.data.\*.id | string | opencti case id | case-rfi--yz567
action_result.data.\*.name | string |  | Threat Intelligence Request
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created case RFI
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create case rft'
Create a new Case-RFT (Request for Takedown) in OpenCTI

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the RFT | string | 
**description** | optional | Description of the RFT | string | 
**priority** | optional | Priority (P1, P2, P3, P4) | string | 
**severity** | optional | Severity (low, medium, high, critical) | string | 
**takedown_types** | optional | Types of takedown requested | string | 
**assignee_id** | optional | ID of the assignee | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.name | string |  | Malicious Domain Takedown
action_result.data.\*.id | string | opencti case id | case-rft--abc890
action_result.data.\*.name | string |  | Malicious Domain Takedown
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created case RFT
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create incident'
Create a new incident in OpenCTI

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the incident | string | 
**description** | optional | Description of the incident | string | 
**first_seen** | optional | First seen date (ISO 8601 format) | string | 
**last_seen** | optional | Last seen date (ISO 8601 format) | string | 
**objective** | optional | Incident objective | string | 
**severity** | optional | Severity level | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.name | string |  | Data Breach 2025
action_result.data.\*.id | string | opencti incident id | incident--def123
action_result.data.\*.name | string |  | Data Breach 2025
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created incident
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'search observables'
Search for STIX cyber observables in OpenCTI

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**search_term** | optional | Search term | string | 
**observable_types** | optional | Comma-separated list of observable types | string | 
**limit** | optional | Maximum number of results | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.search_term | string |  | 192.168
action_result.data.\*.id | string | opencti observable id | ipv4-addr--ghi456
action_result.data.\*.observable_value | string |  | 192.168.1.1
action_result.data.\*.entity_type | string |  | IPv4-Addr
action_result.summary.total_observables | numeric |  | 10
action_result.message | string |  | Found 10 observables
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create observable'
Create a new STIX cyber observable in OpenCTI

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**observable_type** | required | Type of observable | string | 
**observable_value** | required | Value of the observable | string | 
**description** | optional | Description | string | 
**x_opencti_score** | optional | Threat score (0-100) | numeric | 
**labels** | optional | Comma-separated list of labels | string | 
**marking_refs** | optional | Comma-separated list of marking definition IDs | string | 
**create_indicator** | optional | Create an indicator from this observable | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.observable_type | string |  | IPv4-Addr
action_result.parameter.observable_value | string |  | 192.168.1.100
action_result.data.\*.id | string | opencti observable id | ipv4-addr--jkl789
action_result.data.\*.observable_value | string |  | 192.168.1.100
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created observable
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create report'
Create a new report in OpenCTI

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the report | string | 
**description** | optional | Description | string | 
**published** | required | Published date (ISO 8601 format) | string | 
**report_types** | optional | Comma-separated list of report types | string | 
**x_opencti_report_status** | optional | Report status | string | 
**confidence** | optional | Confidence level (0-100) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.name | string |  | Threat Analysis Report Q1 2025
action_result.data.\*.id | string | opencti report id | report--mno012
action_result.data.\*.name | string |  | Threat Analysis Report Q1 2025
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created report
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create grouping'
Create a new grouping in OpenCTI

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the grouping | string | 
**description** | optional | Description | string | 
**context** | required | Grouping context | string | 
**confidence** | optional | Confidence level (0-100) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.name | string |  | APT Campaign Indicators
action_result.data.\*.id | string | opencti grouping id | grouping--pqr345
action_result.data.\*.name | string |  | APT Campaign Indicators
action_result.summary.created | boolean |  | True
action_result.message | string |  | Successfully created grouping
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'add object to report'
Add an object to an existing report

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_id** | required | ID of the report | string | opencti report id
**object_id** | required | ID of the object to add | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.report_id | string | opencti report id | report--mno012
action_result.parameter.object_id | string |  | indicator--abc123
action_result.summary.added | boolean |  | True
action_result.message | string |  | Successfully added object to report
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'add object to grouping'
Add an object to an existing grouping

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**grouping_id** | required | ID of the grouping | string | opencti grouping id
**object_id** | required | ID of the object to add | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.grouping_id | string | opencti grouping id | grouping--pqr345
action_result.parameter.object_id | string |  | malware--def456
action_result.summary.added | boolean |  | True
action_result.message | string |  | Successfully added object to grouping
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'create label'
Create a new label in OpenCTI with predictive color generation

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**value** | required | Label value/name | string | 
**color** | optional | Label color (hex format, e.g., #FF0000). If not provided, a predictive color will be generated based on the label value | string | 
**stix_id** | optional | Custom STIX ID for the label | string | 
**x_opencti_stix_ids** | optional | Additional STIX IDs (comma-separated) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.value | string |  | malware
action_result.parameter.color | string |  | #FF6B6B
action_result.parameter.stix_id | string |  | label--custom-id
action_result.parameter.x_opencti_stix_ids | string |  | id1,id2,id3
action_result.data.\*.id | string |  | label--abc123
action_result.data.\*.value | string |  | malware
action_result.data.\*.color | string |  | #FF6B6B
action_result.summary.label_created | boolean |  | True
action_result.summary.label_id | string |  | label--abc123
action_result.summary.label_value | string |  | malware
action_result.summary.label_color | string |  | #FF6B6B
action_result.message | string |  | Successfully created label 'malware' with color #FF6B6B
summary.total_objects | numeric |  | 1
summary.total_objects_successful | numeric |  | 1

## action: 'bulk create entities'
Bulk create multiple entities of the same type in OpenCTI

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**entity_type** | required | Type of entities to create (indicator, observable, malware, threat-actor, etc.) | string | 
**entities_json** | required | JSON array of entity objects to create | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.entity_type | string |  | observable
action_result.data.\*.created_entities | string |  | 
action_result.data.\*.failed_entities | string |  | 
action_result.summary.total_entities | numeric |  | 10
action_result.summary.created_count | numeric |  | 8
action_result.summary.failed_count | numeric |  | 2
action_result.summary.entity_type | string |  | observable
action_result.message | string |  | Successfully created 8/10 observable entities (2 failed)

## action: 'bulk add to container'
Bulk add multiple objects to a container (report, grouping, or case)

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_type** | required | Type of container (report, grouping, case-incident, case-rfi, case-rft) | string | 
**container_id** | required | ID of the container | string | 
**object_ids** | required | Comma-separated list or JSON array of object IDs to add | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.container_type | string |  | report
action_result.parameter.container_id | string |  | report--abc123
action_result.data.\*.added_objects | string |  | 
action_result.data.\*.failed_objects | string |  | 
action_result.summary.total_objects | numeric |  | 5
action_result.summary.added_count | numeric |  | 5
action_result.summary.failed_count | numeric |  | 0
action_result.message | string |  | Successfully added 5/5 objects to report

## action: 'add object to case incident'
Add an object to a case incident

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**case_id** | required | ID of the case incident | string | 
**object_id** | required | ID of the object to add | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.case_id | string |  | case-incident--abc123
action_result.parameter.object_id | string |  | indicator--def456
action_result.data.\*.added | boolean |  | True
action_result.summary.object_added | boolean |  | True
action_result.message | string |  | Successfully added object to case incident

## action: 'add object to case rfi'
Add an object to a case RFI (Request for Information)

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**case_id** | required | ID of the case RFI | string | 
**object_id** | required | ID of the object to add | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.case_id | string |  | case-rfi--abc123
action_result.parameter.object_id | string |  | malware--def456
action_result.data.\*.added | boolean |  | True
action_result.summary.object_added | boolean |  | True
action_result.message | string |  | Successfully added object to case RFI

## action: 'add object to case rft'
Add an object to a case RFT (Request for Takedown)

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**case_id** | required | ID of the case RFT | string | 
**object_id** | required | ID of the object to add | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.case_id | string |  | case-rft--abc123
action_result.parameter.object_id | string |  | threat-actor--def456
action_result.data.\*.added | boolean |  | True
action_result.summary.object_added | boolean |  | True
action_result.message | string |  | Successfully added object to case RFT

## action: 'enrich artifact'
Enrich a Splunk artifact by searching for an observable in OpenCTI and retrieving associated objects

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact_value** | required | Value of the artifact to enrich (IP, domain, hash, etc.) | string | `ip` `domain` `url` `hash` `email`
**artifact_type** | optional | Type of the artifact | string | 
**include_relationships** | optional | Include related entities and relationships (default: true) | boolean | 
**include_indicators** | optional | Include associated indicators (default: true) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.parameter.artifact_value | string | `ip` `domain` `url` `hash` `email` | 192.168.1.1
action_result.parameter.artifact_type | string |  | ip
action_result.data.\*.observables | string |  | 
action_result.data.\*.indicators | string |  | 
action_result.data.\*.relationships | string |  | 
action_result.data.\*.threat_actors | string |  | 
action_result.data.\*.malware | string |  | 
action_result.data.\*.campaigns | string |  | 
action_result.data.\*.intrusion_sets | string |  | 
action_result.summary.enrichment_found | boolean |  | True
action_result.summary.observable_count | numeric |  | 1
action_result.summary.indicator_count | numeric |  | 3
action_result.summary.relationship_count | numeric |  | 5
action_result.summary.threat_actor_count | numeric |  | 2
action_result.summary.malware_count | numeric |  | 1
action_result.message | string |  | Found 1 observables and 3 indicators for 192.168.1.1

## action: 'bulk enrich artifacts'
Bulk enrich multiple Splunk artifacts by searching for observables in OpenCTI

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifacts_json** | required | JSON array of artifact objects with 'value' and optional 'type' fields | string | 
**include_relationships** | optional | Include related entities and relationships (default: false) | boolean | 
**include_indicators** | optional | Include associated indicators (default: true) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  | success failed
action_result.data.\*.enriched_artifacts | string |  | 
action_result.data.\*.not_found_artifacts | string |  | 
action_result.summary.total_artifacts | numeric |  | 20
action_result.summary.enriched_count | numeric |  | 15
action_result.summary.not_found_count | numeric |  | 5
action_result.summary.total_indicators | numeric |  | 45
action_result.summary.total_threat_context | numeric |  | 12
action_result.message | string |  | Successfully enriched 15/20 artifacts (5 not found)

---
Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Filigran.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied. See the License for the specific language governing permissions
and limitations under the License.
