# File: opencti_consts.py
#
# Copyright (c) 2025 Filigran
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

# Error messages
ERROR_MESSAGE_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and/or action parameters."
VALID_INTEGER_MSG = "Please provide a valid integer value in the '{param}' parameter"
NON_NEGATIVE_INTEGER_MSG = (
    "Please provide a valid non-negative integer value in the '{param}' parameter"
)
NON_ZERO_POSITIVE_INTEGER_MSG = (
    "Please provide a valid positive integer value in the '{param}' parameter"
)

# OpenCTI specific constants
DEFAULT_LIMIT = 50
MAX_LIMIT = 500

# Indicator types
INDICATOR_TYPES = [
    "IPv4-Addr",
    "IPv6-Addr",
    "Domain-Name",
    "Hostname",
    "Email-Addr",
    "URL",
    "File-SHA256",
    "File-SHA1",
    "File-MD5",
    "StixFile",
    "Directory",
    "Registry-Key",
    "Registry-Key-Value",
    "X509-Certificate",
    "Mutex",
    "Process",
    "Software",
    "User-Account",
    "Windows-Registry-Key",
    "Windows-Registry-Value-Type",
    "Cryptographic-Key",
    "Cryptocurrency-Wallet",
    "User-Agent",
    "Bank-Account",
    "Phone-Number",
    "Payment-Card",
]

# Entity types
ENTITY_TYPES = [
    "Attack-Pattern",
    "Campaign",
    "Course-Of-Action",
    "Identity",
    "Indicator",
    "Infrastructure",
    "Intrusion-Set",
    "Malware",
    "Threat-Actor",
    "Tool",
    "Vulnerability",
    "Incident",
    "City",
    "Country",
    "Region",
    "Administrative-Area",
]

# Relationship types
RELATIONSHIP_TYPES = [
    "uses",
    "targets",
    "related-to",
    "mitigates",
    "impersonates",
    "indicates",
    "comes-after",
    "attributed-to",
    "variant-of",
    "originates-from",
    "delivers",
    "drops",
    "exploits",
    "hosts",
    "downloads",
    "communicates-with",
    "consists-of",
    "controls",
    "authored-by",
    "beacons-to",
    "exfiltrates-to",
]

# Threat actor types
THREAT_ACTOR_TYPES = [
    "threat-actor-individual",
    "threat-actor-group",
    "nation-state",
    "insider",
    "activist",
    "competitor",
    "crime-syndicate",
    "criminal",
    "hacker",
    "sensationalist",
    "spy",
    "terrorist",
    "unknown",
]

# Malware types
MALWARE_TYPES = [
    "adware",
    "backdoor",
    "bot",
    "bootkit",
    "ddos",
    "downloader",
    "dropper",
    "exploit-kit",
    "keylogger",
    "loader",
    "miner",
    "password-stealer",
    "pos-malware",
    "ransomware",
    "remote-access-trojan",
    "resource-exploitation",
    "rogue-security-software",
    "rootkit",
    "screen-capture",
    "spyware",
    "trojan",
    "unknown",
    "virus",
    "webshell",
    "wiper",
    "worm",
]

# Attack pattern kill chain phases
KILL_CHAIN_PHASES = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command-and-control",
    "actions-on-objectives",
]

# Marking definitions
MARKING_DEFINITIONS = [
    "TLP:CLEAR",
    "TLP:WHITE",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
]

# Sophistication levels
SOPHISTICATION_LEVELS = [
    "none",
    "minimal",
    "intermediate",
    "advanced",
    "expert",
    "innovator",
    "strategic",
]

# Resource levels
RESOURCE_LEVELS = [
    "individual",
    "club",
    "contest",
    "team",
    "organization",
    "government",
]

# Primary motivations
PRIMARY_MOTIVATIONS = [
    "accidental",
    "coercion",
    "dominance",
    "ideology",
    "notoriety",
    "organizational-gain",
    "personal-gain",
    "personal-satisfaction",
    "revenge",
    "unpredictable",
]

# CVSS severity levels
CVSS_SEVERITY_LEVELS = ["None", "Low", "Medium", "High", "Critical"]

# CVSS attack vectors
CVSS_ATTACK_VECTORS = ["Network", "Adjacent", "Local", "Physical"]

# CVSS impact levels
CVSS_IMPACT_LEVELS = ["None", "Low", "High"]

# Confidence levels
CONFIDENCE_LEVELS = {"Low": 15, "Medium": 50, "High": 75, "Very High": 90}

# Observable types
OBSERVABLE_TYPES = [
    "Artifact",
    "Autonomous-System",
    "Bank-Account",
    "Cryptocurrency-Wallet",
    "Cryptographic-Key",
    "Directory",
    "Domain-Name",
    "Email-Addr",
    "Email-Message",
    "Email-Mime-Part-Type",
    "Hostname",
    "IPv4-Addr",
    "IPv6-Addr",
    "Mac-Addr",
    "Media-Content",
    "Mutex",
    "Network-Traffic",
    "Payment-Card",
    "Person",
    "Phone-Number",
    "Process",
    "Software",
    "StixFile",
    "Text",
    "Tracking-Number",
    "URL",
    "User-Account",
    "User-Agent",
    "Windows-Registry-Key",
    "Windows-Registry-Value-Type",
    "X509-Certificate",
]

# Case priorities
CASE_PRIORITIES = ["P1", "P2", "P3", "P4"]

# Case severities
CASE_SEVERITIES = ["low", "medium", "high", "critical"]

# Report types
REPORT_TYPES = ["internal-report", "external-report", "threat-report"]

# Grouping contexts
GROUPING_CONTEXTS = ["suspicious-activity", "malware-analysis", "unspecified"]
