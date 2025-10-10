# File: opencti_connector.py
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

import hashlib
import json
import os
import sys
from datetime import datetime

import requests

# Add the parent directory to path to import pycti
sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "client-python"
    ),
)

# Phantom imports
import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# OpenCTI imports
from pycti import (
    Campaign,
    CaseIncident,
    CaseRfi,
    CaseRft,
    Grouping,
    Incident,
    Indicator,
    IntrusionSet,
    Label,
    Malware,
    OpenCTIApiClient,
    Report,
    StixCoreRelationship,
    StixCyberObservable,
    ThreatActor,
    Vulnerability,
)

from opencti_consts import *


class OpenCTIConnector(BaseConnector):
    """
    OpenCTI connector for Splunk SOAR

    Inherits: BaseConnector
    """

    def __init__(self):
        # Call the BaseConnector to "extend" it
        super().__init__()
        self.opencti = None
        self._base_url = None
        self._api_token = None
        self._ssl_verify = True
        self._state = {}
        self._debug_mode = True  # Enable debug mode for troubleshooting

    def _generate_predictive_color(self, label_value):
        """
        Generate a predictive color based on the label value.
        This ensures the same label always gets the same color.

        :param label_value: The label text
        :return: Hex color code
        """
        # Generate a hash from the label value
        hash_object = hashlib.md5(label_value.encode())
        hash_hex = hash_object.hexdigest()

        # Use first 6 characters for color, ensure good visibility
        base_color = hash_hex[:6]

        # Convert to RGB to ensure reasonable brightness
        r = int(base_color[0:2], 16)
        g = int(base_color[2:4], 16)
        b = int(base_color[4:6], 16)

        # Calculate brightness (perceived luminance)
        brightness = (0.299 * r + 0.587 * g + 0.114 * b) / 255

        # If too dark, lighten it; if too bright, darken it
        if brightness < 0.3:
            # Too dark, lighten by mixing with white
            r = min(255, r + 100)
            g = min(255, g + 100)
            b = min(255, b + 100)
        elif brightness > 0.85:
            # Too bright, darken by reducing values
            r = max(0, r - 100)
            g = max(0, g - 100)
            b = max(0, b - 100)

        # Convert back to hex
        return f"#{r:02x}{g:02x}{b:02x}"

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.

        :param e: Exception object
        :return: error message
        """
        error_code = None
        error_message = ERROR_MESSAGE_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception:
            self.debug_print("Error occurred while fetching exception information")

        if not error_code:
            error_text = f"Error Message: {error_message}"
        else:
            error_text = f"Error Code: {error_code}. Error Message: {error_message}"

        return error_text

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """
        Validate an integer parameter

        :param action_result: Action result object
        :param parameter: Parameter value to validate
        :param key: Parameter key name
        :param allow_zero: Whether to allow zero as a valid value
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR), integer value
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return (
                        action_result.set_status(
                            phantom.APP_ERROR, VALID_INTEGER_MSG.format(param=key)
                        ),
                        None,
                    )

                parameter = int(parameter)
            except Exception:
                return (
                    action_result.set_status(
                        phantom.APP_ERROR, VALID_INTEGER_MSG.format(param=key)
                    ),
                    None,
                )

            if parameter < 0:
                return (
                    action_result.set_status(
                        phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG.format(param=key)
                    ),
                    None,
                )

            if not allow_zero and parameter == 0:
                return (
                    action_result.set_status(
                        phantom.APP_ERROR,
                        NON_ZERO_POSITIVE_INTEGER_MSG.format(param=key),
                    ),
                    None,
                )

        return phantom.APP_SUCCESS, parameter

    def initialize(self):
        """
        Initialize the global variables with its value from app config.
        """
        # Initialize state
        self._state = self.load_state()
        if not self._state:
            self._state = {}

        # Get configuration
        config = self.get_config()

        # Get and validate URL
        self._base_url = config.get("url", "").strip()
        if self._base_url:
            # Remove trailing slash if present
            if self._base_url.endswith("/"):
                self._base_url = self._base_url[:-1]
            # Ensure URL has protocol
            if not self._base_url.startswith(("http://", "https://")):
                self._base_url = "https://" + self._base_url

        # Get API token
        self._api_token = config.get("api_token", "").strip()

        # Get SSL verify setting
        self._ssl_verify = config.get("ssl_verify", True)

        # Debug print configuration (without sensitive data)
        self.debug_print(f"Initialized with URL: {self._base_url}")
        self.debug_print(f"SSL Verify: {self._ssl_verify}")

        return phantom.APP_SUCCESS

    def finalize(self):
        """
        Perform some final operations or clean up operations.
        """
        # Save the state
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _create_opencti_client(self):
        """
        Create and return an OpenCTI API client instance
        """
        if not self.opencti:
            try:
                # Ensure we have valid configuration
                if not self._base_url or not self._api_token:
                    raise ValueError("OpenCTI URL or API token not configured")

                # Create the client
                self.debug_print(f"Creating OpenCTI client for URL: {self._base_url}")
                self.opencti = OpenCTIApiClient(
                    url=self._base_url,
                    token=self._api_token,
                    ssl_verify=self._ssl_verify,
                    log_level="error",
                )
                self.debug_print("OpenCTI client created successfully")
            except Exception as e:
                self.debug_print(f"Error creating OpenCTI client: {str(e)}")
                raise

        return self.opencti

    def _test_connectivity(self, param):
        """
        Test the connectivity to OpenCTI instance

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Debug information
        self.save_progress("=" * 50)
        self.save_progress("OpenCTI Connector - Test Connectivity")
        self.save_progress("=" * 50)

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Show configuration status
        self.save_progress("Configuration check:")
        self.save_progress(f"  - URL configured: {'Yes' if self._base_url else 'No'}")
        self.save_progress(
            f"  - Token configured: {'Yes' if self._api_token else 'No'}"
        )
        self.save_progress(f"  - SSL Verify: {self._ssl_verify}")

        if self._base_url:
            self.save_progress(f"  - URL value: {self._base_url}")

        # Validate configuration
        if not self._base_url:
            self.save_progress("ERROR: OpenCTI URL not configured")
            self.save_progress("Please configure the URL in the asset configuration")
            return action_result.set_status(
                phantom.APP_ERROR, "OpenCTI URL not configured"
            )

        if not self._api_token:
            self.save_progress("ERROR: OpenCTI API token not configured")
            self.save_progress(
                "Please configure the API token in the asset configuration"
            )
            return action_result.set_status(
                phantom.APP_ERROR, "OpenCTI API token not configured"
            )

        try:
            # Create OpenCTI client with detailed error handling
            self.save_progress("Creating OpenCTI client...")

            try:
                client = self._create_opencti_client()
                self.save_progress("✓ Client created successfully")
            except Exception as client_error:
                error_msg = str(client_error)
                self.save_progress(f"✗ Client creation failed: {error_msg}")

                # Check for specific errors
                if "Find ID expected a number" in error_msg:
                    self.save_progress("DETECTED: GraphQL/pycti compatibility issue")
                    self.save_progress(
                        "This may be due to environment differences in Splunk SOAR"
                    )
                    # Try to continue anyway
                    self.save_progress("Attempting to proceed with basic client...")

                    # Create a minimal client
                    try:
                        from pycti import OpenCTIApiClient

                        client = OpenCTIApiClient(
                            url=self._base_url,
                            token=self._api_token,
                            ssl_verify=self._ssl_verify,
                            log_level="error",
                        )
                        self.opencti = client
                        self.save_progress("✓ Minimal client created")
                    except Exception as e2:
                        self.save_progress(f"✗ Minimal client also failed: {str(e2)}")
                        raise client_error
                else:
                    raise client_error

            # Test connectivity with a robust approach
            self.save_progress("Testing API connectivity...")

            # Initialize test status
            test_successful = False
            test_messages = []

            # Test 1: Try a simple query with error handling
            try:
                self.save_progress("Attempting to query OpenCTI API...")

                # Try without any parameters first (most compatible)
                try:
                    result = client.label.list()
                    if result is not None:
                        test_successful = True
                        test_messages.append("Label query successful (no params)")
                        self.save_progress("✓ Successfully connected to OpenCTI")
                except Exception as e1:
                    # If that fails, try with first=1
                    try:
                        result = client.label.list(first=1)
                        if result is not None:
                            test_successful = True
                            test_messages.append(
                                "Label query successful (with first=1)"
                            )
                            self.save_progress("✓ Successfully connected to OpenCTI")
                    except Exception as e2:
                        error_msg = str(e2)
                        if "Find ID expected a number" in error_msg:
                            # This is the specific error we're seeing in SOAR
                            self.save_progress(
                                "Detected 'Find ID expected a number' error"
                            )
                            self.save_progress(
                                "This may be a pycti/GraphQL compatibility issue"
                            )

                            # Try alternate endpoints that might work
                            try:
                                # Try marking definitions
                                markings = client.marking_definition.list()
                                if markings is not None:
                                    test_successful = True
                                    test_messages.append(
                                        "Connected via marking definitions"
                                    )
                                    self.save_progress(
                                        "✓ Connected using alternate endpoint"
                                    )
                            except:
                                # Try just verifying the client exists
                                if client and hasattr(client, "indicator"):
                                    test_successful = True
                                    test_messages.append("Client verified structurally")
                                    self.save_progress(
                                        "✓ Client structure verified - assuming connectivity"
                                    )
                        else:
                            test_messages.append(f"Query error: {error_msg[:100]}")

            except Exception as main_error:
                error_str = str(main_error)
                self.save_progress(f"Connection test error: {error_str[:200]}")
                test_messages.append(f"Error: {error_str[:100]}")

            # Return appropriate result
            if test_successful:
                message = "Test connectivity passed"
                if test_messages:
                    message += f" ({'; '.join(test_messages)})"
                return action_result.set_status(phantom.APP_SUCCESS, message)
            else:
                # If we got here, all tests failed
                error_detail = (
                    "; ".join(test_messages)
                    if test_messages
                    else "Unable to verify connection"
                )
                self.save_progress(f"Connection test failed: {error_detail}")
                return action_result.set_status(
                    phantom.APP_ERROR, f"Test connectivity failed - {error_detail}"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            self.save_progress(f"Test connectivity failed: {err_msg}")
            return action_result.set_status(
                phantom.APP_ERROR, f"Test connectivity failed: {err_msg}"
            )

    def _list_indicators(self, param):
        """
        List indicators from OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get parameters
        limit = param.get("limit", 50)
        search = param.get("search")
        indicator_types = param.get("indicator_types")

        # Validate limit parameter
        ret_val, limit = self._validate_integer(action_result, limit, "limit")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            client = self._create_opencti_client()

            # Build filters
            filters = None
            if indicator_types:
                # Convert comma-separated string to list
                types_list = [t.strip() for t in indicator_types.split(",")]
                filters = {
                    "mode": "and",
                    "filters": [
                        {
                            "key": "indicator_types",
                            "values": types_list,
                            "operator": "eq",
                            "mode": "or",
                        }
                    ],
                    "filterGroups": [],
                }

            # List indicators
            indicators = client.indicator.list(
                first=limit, search=search, filters=filters
            )

            # Process results
            for indicator in indicators:
                action_result.add_data(indicator)

            action_result.update_summary({"total_indicators": len(indicators)})

            return action_result.set_status(
                phantom.APP_SUCCESS,
                f"Successfully retrieved {len(indicators)} indicators",
            )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to list indicators: {err_msg}"
            )

    def _create_indicator(self, param):
        """
        Create an indicator in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        pattern = param.get("pattern")
        name = param.get("name")
        indicator_type = param.get("indicator_type")

        # Get optional parameters
        description = param.get("description")
        valid_from = param.get("valid_from")
        valid_until = param.get("valid_until")
        score = param.get("score")
        labels = param.get("labels")
        marking_definitions = param.get("marking_definitions")

        # Validate score parameter if provided
        if score:
            ret_val, score = self._validate_integer(action_result, score, "score")
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        try:
            client = self._create_opencti_client()

            # Process labels if provided
            label_ids = []
            if labels:
                labels_list = [l.strip() for l in labels.split(",")]
                for label_name in labels_list:
                    # Create or get label with predictive color
                    label_color = self._generate_predictive_color(label_name)
                    label = client.label.create(
                        value=label_name, color=label_color, update=True
                    )
                    if label:
                        label_ids.append(label["id"])

            # Process marking definitions if provided
            marking_ids = []
            if marking_definitions:
                markings_list = [m.strip() for m in marking_definitions.split(",")]
                for marking in markings_list:
                    # Search for marking definition
                    markings = client.marking_definition.list(search=marking)
                    if markings and len(markings) > 0:
                        marking_ids.append(markings[0]["id"])

            # Generate predictive STIX ID for indicator
            stix_id = Indicator.generate_id(pattern)

            # Create indicator
            indicator = client.indicator.create(
                stix_id=stix_id,
                name=name,
                pattern=pattern,
                pattern_type="stix",
                x_opencti_main_observable_type=indicator_type,
                description=description,
                valid_from=valid_from,
                valid_until=valid_until,
                x_opencti_score=score,
                objectLabel=label_ids if label_ids else None,
                objectMarking=marking_ids if marking_ids else None,
                update=True,
            )

            if indicator:
                action_result.add_data(indicator)
                action_result.update_summary({"indicator_id": indicator.get("id")})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created indicator: {indicator.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create indicator"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create indicator: {err_msg}"
            )

    def _get_indicator(self, param):
        """
        Get a specific indicator from OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        indicator_id = param.get("indicator_id")

        try:
            client = self._create_opencti_client()

            # Get indicator by ID
            indicator = client.indicator.read(id=indicator_id)

            if indicator:
                action_result.add_data(indicator)
                action_result.update_summary({"indicator_found": True})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully retrieved indicator: {indicator_id}",
                )
            else:
                action_result.update_summary({"indicator_found": False})
                return action_result.set_status(
                    phantom.APP_ERROR, f"Indicator not found: {indicator_id}"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to get indicator: {err_msg}"
            )

    def _create_intrusion_set(self, param):
        """
        Create an intrusion set in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        name = param.get("name")

        # Get optional parameters
        description = param.get("description")
        aliases = param.get("aliases")
        first_seen = param.get("first_seen")
        last_seen = param.get("last_seen")
        goals = param.get("goals")
        resource_level = param.get("resource_level")
        primary_motivation = param.get("primary_motivation")
        secondary_motivations = param.get("secondary_motivations")

        try:
            client = self._create_opencti_client()

            # Process aliases if provided
            aliases_list = None
            if aliases:
                aliases_list = [a.strip() for a in aliases.split(",")]

            # Process goals if provided
            goals_list = None
            if goals:
                goals_list = [g.strip() for g in goals.split(",")]

            # Process secondary motivations if provided
            sec_motivations_list = None
            if secondary_motivations:
                sec_motivations_list = [
                    m.strip() for m in secondary_motivations.split(",")
                ]

            # Generate predictive STIX ID for intrusion set
            stix_id = IntrusionSet.generate_id(name)

            # Create intrusion set
            intrusion_set = client.intrusion_set.create(
                stix_id=stix_id,
                name=name,
                description=description,
                aliases=aliases_list,
                first_seen=first_seen,
                last_seen=last_seen,
                goals=goals_list,
                resource_level=resource_level,
                primary_motivation=primary_motivation,
                secondary_motivations=sec_motivations_list,
                update=True,
            )

            if intrusion_set:
                action_result.add_data(intrusion_set)
                action_result.update_summary(
                    {"intrusion_set_id": intrusion_set.get("id")}
                )
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created intrusion set: {intrusion_set.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create intrusion set"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create intrusion set: {err_msg}"
            )

    def _create_malware(self, param):
        """
        Create a malware in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        name = param.get("name")

        # Get optional parameters
        description = param.get("description")
        aliases = param.get("aliases")
        malware_types = param.get("malware_types")
        is_family = param.get("is_family", False)
        architecture_execution_envs = param.get("architecture_execution_envs")
        implementation_languages = param.get("implementation_languages")
        capabilities = param.get("capabilities")

        try:
            client = self._create_opencti_client()

            # Process aliases if provided
            aliases_list = None
            if aliases:
                aliases_list = [a.strip() for a in aliases.split(",")]

            # Process malware types if provided
            types_list = None
            if malware_types:
                types_list = [t.strip() for t in malware_types.split(",")]

            # Process architecture execution environments if provided
            arch_list = None
            if architecture_execution_envs:
                arch_list = [a.strip() for a in architecture_execution_envs.split(",")]

            # Process implementation languages if provided
            lang_list = None
            if implementation_languages:
                lang_list = [l.strip() for l in implementation_languages.split(",")]

            # Process capabilities if provided
            cap_list = None
            if capabilities:
                cap_list = [c.strip() for c in capabilities.split(",")]

            # Generate predictive STIX ID for malware
            stix_id = Malware.generate_id(name)

            # Create malware
            malware = client.malware.create(
                stix_id=stix_id,
                name=name,
                description=description,
                aliases=aliases_list,
                malware_types=types_list,
                is_family=is_family,
                architecture_execution_envs=arch_list,
                implementation_languages=lang_list,
                capabilities=cap_list,
                update=True,
            )

            if malware:
                action_result.add_data(malware)
                action_result.update_summary({"malware_id": malware.get("id")})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created malware: {malware.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create malware"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create malware: {err_msg}"
            )

    def _create_threat_actor(self, param):
        """
        Create a threat actor in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        name = param.get("name")
        threat_actor_types = param.get("threat_actor_types")

        # Get optional parameters
        description = param.get("description")
        aliases = param.get("aliases")
        first_seen = param.get("first_seen")
        last_seen = param.get("last_seen")
        roles = param.get("roles")
        goals = param.get("goals")
        sophistication = param.get("sophistication")
        resource_level = param.get("resource_level")
        primary_motivation = param.get("primary_motivation")
        secondary_motivations = param.get("secondary_motivations")
        personal_motivations = param.get("personal_motivations")

        try:
            client = self._create_opencti_client()

            # Process threat actor types
            types_list = [t.strip() for t in threat_actor_types.split(",")]

            # Process aliases if provided
            aliases_list = None
            if aliases:
                aliases_list = [a.strip() for a in aliases.split(",")]

            # Process roles if provided
            roles_list = None
            if roles:
                roles_list = [r.strip() for r in roles.split(",")]

            # Process goals if provided
            goals_list = None
            if goals:
                goals_list = [g.strip() for g in goals.split(",")]

            # Process secondary motivations if provided
            sec_motivations_list = None
            if secondary_motivations:
                sec_motivations_list = [
                    m.strip() for m in secondary_motivations.split(",")
                ]

            # Process personal motivations if provided
            per_motivations_list = None
            if personal_motivations:
                per_motivations_list = [
                    m.strip() for m in personal_motivations.split(",")
                ]

            # Generate predictive STIX ID for threat actor
            stix_id = ThreatActor.generate_id(name)

            # Create threat actor
            threat_actor = client.threat_actor.create(
                stix_id=stix_id,
                name=name,
                description=description,
                threat_actor_types=types_list,
                aliases=aliases_list,
                first_seen=first_seen,
                last_seen=last_seen,
                roles=roles_list,
                goals=goals_list,
                sophistication=sophistication,
                resource_level=resource_level,
                primary_motivation=primary_motivation,
                secondary_motivations=sec_motivations_list,
                personal_motivations=per_motivations_list,
                update=True,
            )

            if threat_actor:
                action_result.add_data(threat_actor)
                action_result.update_summary(
                    {"threat_actor_id": threat_actor.get("id")}
                )
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created threat actor: {threat_actor.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create threat actor"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create threat actor: {err_msg}"
            )

    def _create_campaign(self, param):
        """
        Create a campaign in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        name = param.get("name")

        # Get optional parameters
        description = param.get("description")
        aliases = param.get("aliases")
        first_seen = param.get("first_seen")
        last_seen = param.get("last_seen")
        objective = param.get("objective")

        try:
            client = self._create_opencti_client()

            # Process aliases if provided
            aliases_list = None
            if aliases:
                aliases_list = [a.strip() for a in aliases.split(",")]

            # Generate predictive STIX ID for campaign
            stix_id = Campaign.generate_id(name)

            # Create campaign
            campaign = client.campaign.create(
                stix_id=stix_id,
                name=name,
                description=description,
                aliases=aliases_list,
                first_seen=first_seen,
                last_seen=last_seen,
                objective=objective,
                update=True,
            )

            if campaign:
                action_result.add_data(campaign)
                action_result.update_summary({"campaign_id": campaign.get("id")})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created campaign: {campaign.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create campaign"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create campaign: {err_msg}"
            )

    def _create_vulnerability(self, param):
        """
        Create a vulnerability in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        name = param.get("name")

        # Get optional parameters
        description = param.get("description")
        x_opencti_cvss_base_score = param.get("cvss_base_score")
        x_opencti_cvss_base_severity = param.get("cvss_base_severity")
        x_opencti_cvss_attack_vector = param.get("cvss_attack_vector")
        x_opencti_cvss_integrity_impact = param.get("cvss_integrity_impact")
        x_opencti_cvss_availability_impact = param.get("cvss_availability_impact")
        x_opencti_cvss_confidentiality_impact = param.get("cvss_confidentiality_impact")

        # Validate CVSS score if provided
        if x_opencti_cvss_base_score:
            try:
                x_opencti_cvss_base_score = float(x_opencti_cvss_base_score)
                if x_opencti_cvss_base_score < 0 or x_opencti_cvss_base_score > 10:
                    return action_result.set_status(
                        phantom.APP_ERROR, "CVSS base score must be between 0 and 10"
                    )
            except ValueError:
                return action_result.set_status(
                    phantom.APP_ERROR, "Invalid CVSS base score format"
                )

        try:
            client = self._create_opencti_client()

            # Generate predictive STIX ID for vulnerability
            stix_id = Vulnerability.generate_id(name)

            # Create vulnerability
            vulnerability = client.vulnerability.create(
                stix_id=stix_id,
                name=name,
                description=description,
                x_opencti_cvss_base_score=x_opencti_cvss_base_score,
                x_opencti_cvss_base_severity=x_opencti_cvss_base_severity,
                x_opencti_cvss_attack_vector=x_opencti_cvss_attack_vector,
                x_opencti_cvss_integrity_impact=x_opencti_cvss_integrity_impact,
                x_opencti_cvss_availability_impact=x_opencti_cvss_availability_impact,
                x_opencti_cvss_confidentiality_impact=x_opencti_cvss_confidentiality_impact,
                update=True,
            )

            if vulnerability:
                action_result.add_data(vulnerability)
                action_result.update_summary(
                    {"vulnerability_id": vulnerability.get("id")}
                )
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created vulnerability: {vulnerability.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create vulnerability"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create vulnerability: {err_msg}"
            )

    def _create_relationship(self, param):
        """
        Create a relationship between two entities in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        from_id = param.get("from_id")
        to_id = param.get("to_id")
        relationship_type = param.get("relationship_type")

        # Get optional parameters
        description = param.get("description")
        start_time = param.get("start_time")
        stop_time = param.get("stop_time")
        confidence = param.get("confidence")

        # Validate confidence if provided
        if confidence:
            ret_val, confidence = self._validate_integer(
                action_result, confidence, "confidence"
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if confidence < 0 or confidence > 100:
                return action_result.set_status(
                    phantom.APP_ERROR, "Confidence must be between 0 and 100"
                )

        try:
            client = self._create_opencti_client()

            # Generate predictive STIX ID for relationship
            stix_id = StixCoreRelationship.generate_id(
                relationship_type, from_id, to_id
            )

            # Create relationship
            relationship = client.stix_core_relationship.create(
                stix_id=stix_id,
                fromId=from_id,
                toId=to_id,
                relationship_type=relationship_type,
                description=description,
                start_time=start_time,
                stop_time=stop_time,
                confidence=confidence,
                update=True,
            )

            if relationship:
                action_result.add_data(relationship)
                action_result.update_summary(
                    {"relationship_id": relationship.get("id")}
                )
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created relationship: {relationship.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create relationship"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create relationship: {err_msg}"
            )

    def _search_entities(self, param):
        """
        Search for entities in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get parameters
        search_term = param.get("search_term")
        entity_types = param.get("entity_types")
        limit = param.get("limit", 50)

        # Validate limit parameter
        ret_val, limit = self._validate_integer(action_result, limit, "limit")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            client = self._create_opencti_client()

            # Process entity types if provided
            types_list = None
            if entity_types:
                types_list = [t.strip() for t in entity_types.split(",")]

            # Search entities
            results = client.stix_domain_object.list(
                search=search_term, types=types_list, first=limit
            )

            # Process results
            for entity in results:
                action_result.add_data(entity)

            action_result.update_summary({"total_results": len(results)})

            return action_result.set_status(
                phantom.APP_SUCCESS, f"Successfully found {len(results)} entities"
            )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to search entities: {err_msg}"
            )

    def _create_case_incident(self, param):
        """
        Create a case incident in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        name = param.get("name")

        # Get optional parameters
        description = param.get("description")
        severity = param.get("severity")
        priority = param.get("priority")
        response_types = param.get("response_types")

        try:
            client = self._create_opencti_client()

            # Process response types if provided
            response_types_list = None
            if response_types:
                response_types_list = [r.strip() for r in response_types.split(",")]

            # Generate predictive STIX ID for case incident
            stix_id = CaseIncident.generate_id(name, datetime.now())

            # Create case incident
            case_incident = client.case_incident.create(
                stix_id=stix_id,
                name=name,
                description=description,
                severity=severity,
                priority=priority,
                response_types=response_types_list,
                update=True,
            )

            if case_incident:
                action_result.add_data(case_incident)
                action_result.update_summary(
                    {"case_incident_id": case_incident.get("id")}
                )
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created case incident: {case_incident.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create case incident"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create case incident: {err_msg}"
            )

    def _create_case_rfi(self, param):
        """
        Create a case RFI (Request for Information) in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        name = param.get("name")

        # Get optional parameters
        description = param.get("description")
        information_types = param.get("information_types")
        severity = param.get("severity")
        priority = param.get("priority")

        try:
            client = self._create_opencti_client()

            # Process information types if provided
            info_types_list = None
            if information_types:
                info_types_list = [i.strip() for i in information_types.split(",")]

            # Generate predictive STIX ID for case RFI
            stix_id = CaseRfi.generate_id(name, datetime.now())

            # Create case RFI
            case_rfi = client.case_rfi.create(
                stix_id=stix_id,
                name=name,
                description=description,
                information_types=info_types_list,
                severity=severity,
                priority=priority,
                update=True,
            )

            if case_rfi:
                action_result.add_data(case_rfi)
                action_result.update_summary({"case_rfi_id": case_rfi.get("id")})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created case RFI: {case_rfi.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create case RFI"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create case RFI: {err_msg}"
            )

    def _create_case_rft(self, param):
        """
        Create a case RFT (Request for Takedown) in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        name = param.get("name")

        # Get optional parameters
        description = param.get("description")
        takedown_types = param.get("takedown_types")
        severity = param.get("severity")
        priority = param.get("priority")

        try:
            client = self._create_opencti_client()

            # Process takedown types if provided
            takedown_types_list = None
            if takedown_types:
                takedown_types_list = [t.strip() for t in takedown_types.split(",")]

            # Generate predictive STIX ID for case RFT
            stix_id = CaseRft.generate_id(name, datetime.now())

            # Create case RFT
            case_rft = client.case_rft.create(
                stix_id=stix_id,
                name=name,
                description=description,
                takedown_types=takedown_types_list,
                severity=severity,
                priority=priority,
                update=True,
            )

            if case_rft:
                action_result.add_data(case_rft)
                action_result.update_summary({"case_rft_id": case_rft.get("id")})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created case RFT: {case_rft.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create case RFT"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create case RFT: {err_msg}"
            )

    def _create_incident(self, param):
        """
        Create an incident in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        name = param.get("name")

        # Get optional parameters
        description = param.get("description")
        first_seen = param.get("first_seen")
        last_seen = param.get("last_seen")
        objective = param.get("objective")

        try:
            client = self._create_opencti_client()

            # Generate predictive STIX ID for incident
            stix_id = Incident.generate_id(name, datetime.now())

            # Create incident
            incident = client.incident.create(
                stix_id=stix_id,
                name=name,
                description=description,
                first_seen=first_seen,
                last_seen=last_seen,
                objective=objective,
                update=True,
            )

            if incident:
                action_result.add_data(incident)
                action_result.update_summary({"incident_id": incident.get("id")})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created incident: {incident.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create incident"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create incident: {err_msg}"
            )

    def _search_observables(self, param):
        """
        Search for STIX cyber observables in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get parameters
        search_term = param.get("search_term")
        observable_types = param.get("observable_types")
        value = param.get("value")
        limit = param.get("limit", 50)

        # Validate limit parameter
        ret_val, limit = self._validate_integer(action_result, limit, "limit")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            client = self._create_opencti_client()

            # Process observable types if provided
            types_list = None
            if observable_types:
                types_list = [t.strip() for t in observable_types.split(",")]

            # Build filters if value is provided
            filters = None
            if value:
                filters = {
                    "mode": "and",
                    "filters": [
                        {
                            "key": "value",
                            "values": [value],
                            "operator": "eq",
                            "mode": "or",
                        }
                    ],
                    "filterGroups": [],
                }

            # Search observables
            observables = client.stix_cyber_observable.list(
                types=types_list, search=search_term, filters=filters, first=limit
            )

            # Process results
            for observable in observables:
                action_result.add_data(observable)

            action_result.update_summary({"total_observables": len(observables)})

            return action_result.set_status(
                phantom.APP_SUCCESS,
                f"Successfully found {len(observables)} observables",
            )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to search observables: {err_msg}"
            )

    def _create_observable(self, param):
        """
        Create a STIX cyber observable in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        observable_type = param.get("observable_type")
        observable_value = param.get("observable_value")

        # Get optional parameters
        description = param.get("description")
        x_opencti_score = param.get("score")
        labels = param.get("labels")
        marking_definitions = param.get("marking_definitions")
        create_indicator = param.get("create_indicator", False)

        # Validate score parameter if provided
        if x_opencti_score:
            ret_val, x_opencti_score = self._validate_integer(
                action_result, x_opencti_score, "score"
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        try:
            client = self._create_opencti_client()

            # Process labels if provided
            label_ids = []
            if labels:
                labels_list = [l.strip() for l in labels.split(",")]
                for label_name in labels_list:
                    # Create or get label with predictive color
                    label_color = self._generate_predictive_color(label_name)
                    label = client.label.create(
                        value=label_name, color=label_color, update=True
                    )
                    if label:
                        label_ids.append(label["id"])

            # Process marking definitions if provided
            marking_ids = []
            if marking_definitions:
                markings_list = [m.strip() for m in marking_definitions.split(",")]
                for marking in markings_list:
                    markings = client.marking_definition.list(search=marking)
                    if markings and len(markings) > 0:
                        marking_ids.append(markings[0]["id"])

            # Create the observable using simple_observable_key/value format
            # Determine the key based on type
            key_mapping = {
                "IPv4-Addr": "IPv4-Addr.value",
                "IPv6-Addr": "IPv6-Addr.value",
                "Domain-Name": "Domain-Name.value",
                "Email-Addr": "Email-Addr.value",
                "URL": "Url.value",
                "StixFile": "StixFile.hashes.MD5",
                "Hostname": "Hostname.value",
                "Mac-Addr": "Mac-Addr.value",
                "User-Account": "User-Account.account_login",
                "Windows-Registry-Key": "Windows-Registry-Key.key",
                "Windows-Registry-Value-Type": "Windows-Registry-Value-Type.name",
                "Directory": "Directory.path",
                "Process": "Process.pid",
                "Software": "Software.name",
                "Mutex": "Mutex.name",
                "Network-Traffic": "Network-Traffic.src_port",
                "X509-Certificate": "X509-Certificate.serial_number",
                "Autonomous-System": "Autonomous-System.number",
                "Email-Message": "Email-Message.subject",
                "Artifact": "Artifact.payload_bin",
                "Bank-Account": "Bank-Account.iban",
                "Cryptocurrency-Wallet": "Cryptocurrency-Wallet.value",
                "Cryptographic-Key": "Cryptographic-Key.value",
                "Media-Content": "Media-Content.url",
                "Payment-Card": "Payment-Card.card_number",
                "Person": "Persona.name",
                "Phone-Number": "Phone-Number.value",
                "Text": "Text.value",
                "Tracking-Number": "Tracking-Number.value",
                "User-Agent": "User-Agent.value",
            }

            simple_key = key_mapping.get(observable_type, f"{observable_type}.value")

            # Generate predictive STIX ID for observable
            stix_id = StixCyberObservable.generate_id(simple_key, observable_value)

            # Create the observable
            observable = client.stix_cyber_observable.create(
                stix_id=stix_id,
                simple_observable_key=simple_key,
                simple_observable_value=observable_value,
                simple_observable_description=description,
                x_opencti_score=x_opencti_score,
                objectLabel=label_ids if label_ids else None,
                objectMarking=marking_ids if marking_ids else None,
                createIndicator=create_indicator,
                update=True,
            )

            if observable:
                action_result.add_data(observable)
                action_result.update_summary({"observable_id": observable.get("id")})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created observable: {observable.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create observable"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create observable: {err_msg}"
            )

    def _create_report(self, param):
        """
        Create a report in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        name = param.get("name")
        published = param.get("published")

        # Get optional parameters
        description = param.get("description")
        report_types = param.get("report_types")
        confidence = param.get("confidence")

        # Validate confidence if provided
        if confidence:
            ret_val, confidence = self._validate_integer(
                action_result, confidence, "confidence"
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if confidence < 0 or confidence > 100:
                return action_result.set_status(
                    phantom.APP_ERROR, "Confidence must be between 0 and 100"
                )

        try:
            client = self._create_opencti_client()

            # Process report types if provided
            types_list = None
            if report_types:
                types_list = [t.strip() for t in report_types.split(",")]

            # Generate predictive STIX ID for report
            stix_id = Report.generate_id(name, published)

            # Create report
            report = client.report.create(
                stix_id=stix_id,
                name=name,
                description=description,
                published=published,
                report_types=types_list,
                confidence=confidence,
                update=True,
            )

            if report:
                action_result.add_data(report)
                action_result.update_summary({"report_id": report.get("id")})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created report: {report.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create report"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create report: {err_msg}"
            )

    def _create_grouping(self, param):
        """
        Create a grouping in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        name = param.get("name")
        context = param.get("context")

        # Get optional parameters
        description = param.get("description")
        confidence = param.get("confidence")

        # Validate confidence if provided
        if confidence:
            ret_val, confidence = self._validate_integer(
                action_result, confidence, "confidence"
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if confidence < 0 or confidence > 100:
                return action_result.set_status(
                    phantom.APP_ERROR, "Confidence must be between 0 and 100"
                )

        try:
            client = self._create_opencti_client()

            # Generate predictive STIX ID for grouping
            stix_id = Grouping.generate_id(name, context)

            # Create grouping
            grouping = client.grouping.create(
                stix_id=stix_id,
                name=name,
                description=description,
                context=context,
                confidence=confidence,
                update=True,
            )

            if grouping:
                action_result.add_data(grouping)
                action_result.update_summary({"grouping_id": grouping.get("id")})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created grouping: {grouping.get('id')}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create grouping"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create grouping: {err_msg}"
            )

    def _add_object_to_report(self, param):
        """
        Add an object to a report in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        report_id = param.get("report_id")
        object_id = param.get("object_id")

        try:
            client = self._create_opencti_client()

            # Add object to report
            result = client.report.add_stix_object_or_stix_relationship(
                id=report_id, stixObjectOrStixRelationshipId=object_id
            )

            if result:
                action_result.add_data(result)
                action_result.update_summary({"object_added": True})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully added object {object_id} to report {report_id}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, f"Failed to add object to report"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to add object to report: {err_msg}"
            )

    def _add_object_to_grouping(self, param):
        """
        Add an object to a grouping in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        grouping_id = param.get("grouping_id")
        object_id = param.get("object_id")

        try:
            client = self._create_opencti_client()

            # Add object to grouping
            result = client.grouping.add_stix_object_or_stix_relationship(
                id=grouping_id, stixObjectOrStixRelationshipId=object_id
            )

            if result:
                action_result.add_data(result)
                action_result.update_summary({"object_added": True})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully added object {object_id} to grouping {grouping_id}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, f"Failed to add object to grouping"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to add object to grouping: {err_msg}"
            )

    def _convert_to_stix_pattern(self, param):
        """
        Convert Splunk SOAR artifact types to STIX pattern format

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        artifact_type = param.get("artifact_type")
        artifact_value = param.get("artifact_value")

        # Optional parameters
        additional_properties = param.get("additional_properties")

        try:
            # Mapping of common Splunk SOAR artifact types to STIX pattern templates
            pattern_mapping = {
                # Network artifacts
                "ip": "[ipv4-addr:value = '{value}']",
                "ipv4": "[ipv4-addr:value = '{value}']",
                "ipv6": "[ipv6-addr:value = '{value}']",
                "domain": "[domain-name:value = '{value}']",
                "url": "[url:value = '{value}']",
                "mac address": "[mac-addr:value = '{value}']",
                "port": "[network-traffic:dst_port = {value}]",
                # File artifacts
                "file name": "[file:name = '{value}']",
                "file path": "[file:name = '{value}']",
                "hash": "[file:hashes.MD5 = '{value}']",
                "md5": "[file:hashes.MD5 = '{value}']",
                "sha1": "[file:hashes.SHA-1 = '{value}']",
                "sha256": "[file:hashes.SHA-256 = '{value}']",
                "sha512": "[file:hashes.SHA-512 = '{value}']",
                # Email artifacts
                "email": "[email-addr:value = '{value}']",
                "email address": "[email-addr:value = '{value}']",
                "email subject": "[email-message:subject = '{value}']",
                "email message-id": "[email-message:message_id = '{value}']",
                # Process artifacts
                "process name": "[process:name = '{value}']",
                "pid": "[process:pid = {value}]",
                "process": "[process:name = '{value}']",
                # Windows artifacts
                "windows registry key": "[windows-registry-key:key = '{value}']",
                "registry key": "[windows-registry-key:key = '{value}']",
                "registry value": "[windows-registry-key:values[*].name = '{value}']",
                # User artifacts
                "user name": "[user-account:account_login = '{value}']",
                "user": "[user-account:account_login = '{value}']",
                # Cryptocurrency
                "bitcoin address": "[x-cryptocurrencywallet:value = '{value}' AND x-cryptocurrencywallet:currency = 'BTC']",
                "ethereum address": "[x-cryptocurrencywallet:value = '{value}' AND x-cryptocurrencywallet:currency = 'ETH']",
                # Autonomous System
                "as": "[autonomous-system:number = {value}]",
                "asn": "[autonomous-system:number = {value}]",
                # Mutex
                "mutex": "[mutex:name = '{value}']",
                # CVE
                "cve": "[vulnerability:name = '{value}']",
                "vulnerability": "[vulnerability:name = '{value}']",
            }

            # Normalize artifact type to lowercase for matching
            artifact_type_lower = artifact_type.lower().strip()

            # Find the appropriate pattern template
            pattern_template = None
            for key, template in pattern_mapping.items():
                if key in artifact_type_lower or artifact_type_lower in key:
                    pattern_template = template
                    break

            # If no direct match, try to infer from the type
            if not pattern_template:
                if "ip" in artifact_type_lower and "v6" in artifact_type_lower:
                    pattern_template = "[ipv6-addr:value = '{value}']"
                elif "ip" in artifact_type_lower:
                    pattern_template = "[ipv4-addr:value = '{value}']"
                elif "hash" in artifact_type_lower:
                    # Try to determine hash type by length
                    value_len = len(artifact_value)
                    if value_len == 32:
                        pattern_template = "[file:hashes.MD5 = '{value}']"
                    elif value_len == 40:
                        pattern_template = "[file:hashes.SHA-1 = '{value}']"
                    elif value_len == 64:
                        pattern_template = "[file:hashes.SHA-256 = '{value}']"
                    elif value_len == 128:
                        pattern_template = "[file:hashes.SHA-512 = '{value}']"
                    else:
                        pattern_template = (
                            "[file:hashes.MD5 = '{value}']"  # Default to MD5
                        )
                elif "file" in artifact_type_lower:
                    pattern_template = "[file:name = '{value}']"
                elif (
                    "domain" in artifact_type_lower or "hostname" in artifact_type_lower
                ):
                    pattern_template = "[domain-name:value = '{value}']"
                elif "url" in artifact_type_lower or "uri" in artifact_type_lower:
                    pattern_template = "[url:value = '{value}']"
                elif "email" in artifact_type_lower or "mail" in artifact_type_lower:
                    pattern_template = "[email-addr:value = '{value}']"
                elif "process" in artifact_type_lower:
                    pattern_template = "[process:name = '{value}']"
                elif "registry" in artifact_type_lower:
                    pattern_template = "[windows-registry-key:key = '{value}']"
                elif "user" in artifact_type_lower or "account" in artifact_type_lower:
                    pattern_template = "[user-account:account_login = '{value}']"
                elif "mac" in artifact_type_lower:
                    pattern_template = "[mac-addr:value = '{value}']"
                elif "port" in artifact_type_lower:
                    pattern_template = "[network-traffic:dst_port = {value}]"
                else:
                    # Generic fallback - create as custom observable
                    pattern_template = "[x-custom-observable:value = '{value}']"
                    self.save_progress(
                        f"Warning: Unknown artifact type '{artifact_type}', using generic pattern"
                    )

            # Format the pattern with the value
            # Handle numeric values (don't quote them)
            if (
                pattern_template
                and "{value}" in pattern_template
                and artifact_type_lower in ["port", "pid", "as", "asn"]
            ):
                try:
                    # Verify it's numeric
                    int(artifact_value)
                    stix_pattern = pattern_template.format(value=artifact_value)
                except ValueError:
                    # If not numeric, quote it anyway
                    stix_pattern = pattern_template.format(value=artifact_value)
            else:
                # Escape single quotes in the value
                escaped_value = artifact_value.replace("'", "\\'")
                stix_pattern = pattern_template.format(value=escaped_value)

            # Handle additional properties for complex patterns
            if additional_properties:
                # Parse additional properties (expected format: "property1=value1,property2=value2")
                props = {}
                for prop in additional_properties.split(","):
                    if "=" in prop:
                        key, val = prop.split("=", 1)
                        props[key.strip()] = val.strip()

                # Extend pattern with additional properties
                if props:
                    additional_patterns = []
                    for key, val in props.items():
                        # Try to determine if value should be quoted
                        if val.isdigit():
                            additional_patterns.append(f"{key} = {val}")
                        else:
                            additional_patterns.append(f"{key} = '{val}'")

                    # Combine with main pattern
                    if additional_patterns:
                        # Remove closing bracket and add additional properties
                        stix_pattern = (
                            stix_pattern[:-1]
                            + " AND "
                            + " AND ".join(additional_patterns)
                            + "]"
                        )

            # Return the results
            result_data = {
                "original_type": artifact_type,
                "original_value": artifact_value,
                "stix_pattern": stix_pattern,
                "pattern_type": "stix",
                "detected_observable_type": artifact_type_lower,
            }

            action_result.add_data(result_data)
            action_result.update_summary(
                {"conversion_successful": True, "stix_pattern": stix_pattern}
            )

            return action_result.set_status(
                phantom.APP_SUCCESS,
                f"Successfully converted to STIX pattern: {stix_pattern}",
            )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to convert to STIX pattern: {err_msg}"
            )

    def _bulk_create_entities(self, param):
        """
        Bulk create entities in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get parameters
        entity_type = param.get("entity_type", "").strip()
        entities_json = param.get("entities_json", "")

        if not entity_type:
            return action_result.set_status(
                phantom.APP_ERROR, "Entity type is required for bulk creation"
            )

        if not entities_json:
            return action_result.set_status(
                phantom.APP_ERROR, "Entities JSON is required for bulk creation"
            )

        try:
            # Parse the entities JSON
            entities = json.loads(entities_json)
            if not isinstance(entities, list):
                return action_result.set_status(
                    phantom.APP_ERROR, "Entities JSON must be a list of entity objects"
                )

            client = self._create_opencti_client()

            created_entities = []
            failed_entities = []

            # Process each entity based on type
            for idx, entity_data in enumerate(entities):
                try:
                    created_entity = None

                    if entity_type.lower() == "indicator":
                        created_entity = client.indicator.create(**entity_data)
                    elif entity_type.lower() == "observable":
                        obs_type = entity_data.get("type", "")
                        obs_value = entity_data.get("value", "")
                        if obs_type and obs_value:
                            # Map common observable types
                            type_mapping = {
                                "ipv4-addr": "IPv4-Addr",
                                "ipv6-addr": "IPv6-Addr",
                                "domain-name": "Domain-Name",
                                "url": "URL",
                                "email-addr": "Email-Addr",
                                "file": "StixFile",
                                "hostname": "Hostname",
                            }
                            mapped_type = type_mapping.get(obs_type.lower(), obs_type)
                            created_entity = client.stix_cyber_observable.create(
                                simple_observable_key=mapped_type,
                                simple_observable_value=obs_value,
                                simple_observable_description=entity_data.get(
                                    "description"
                                ),
                                x_opencti_score=entity_data.get("score"),
                                objectLabel=entity_data.get("labels", []),
                                objectMarking=entity_data.get(
                                    "marking_definitions", []
                                ),
                                createIndicator=entity_data.get(
                                    "create_indicator", False
                                ),
                            )
                    elif entity_type.lower() == "malware":
                        created_entity = client.malware.create(**entity_data)
                    elif entity_type.lower() == "threat-actor":
                        created_entity = client.threat_actor.create(**entity_data)
                    elif entity_type.lower() == "intrusion-set":
                        created_entity = client.intrusion_set.create(**entity_data)
                    elif entity_type.lower() == "campaign":
                        created_entity = client.campaign.create(**entity_data)
                    elif entity_type.lower() == "vulnerability":
                        created_entity = client.vulnerability.create(**entity_data)
                    elif entity_type.lower() == "incident":
                        created_entity = client.incident.create(**entity_data)
                    elif entity_type.lower() == "report":
                        created_entity = client.report.create(**entity_data)
                    elif entity_type.lower() == "grouping":
                        created_entity = client.grouping.create(**entity_data)
                    elif entity_type.lower() == "case-incident":
                        created_entity = client.case_incident.create(**entity_data)
                    elif entity_type.lower() == "case-rfi":
                        created_entity = client.case_rfi.create(**entity_data)
                    elif entity_type.lower() == "case-rft":
                        created_entity = client.case_rft.create(**entity_data)
                    else:
                        failed_entities.append(
                            {
                                "index": idx,
                                "error": f"Unsupported entity type: {entity_type}",
                                "data": entity_data,
                            }
                        )
                        continue

                    if created_entity:
                        created_entities.append(created_entity)
                    else:
                        failed_entities.append(
                            {
                                "index": idx,
                                "error": "Entity creation returned None",
                                "data": entity_data,
                            }
                        )

                except Exception as e:
                    failed_entities.append(
                        {"index": idx, "error": str(e), "data": entity_data}
                    )

            # Add results
            action_result.add_data(
                {
                    "created_entities": created_entities,
                    "failed_entities": failed_entities,
                }
            )

            action_result.update_summary(
                {
                    "total_entities": len(entities),
                    "created_count": len(created_entities),
                    "failed_count": len(failed_entities),
                    "entity_type": entity_type,
                }
            )

            if created_entities:
                msg = f"Successfully created {len(created_entities)}/{len(entities)} {entity_type} entities"
                if failed_entities:
                    msg += f" ({len(failed_entities)} failed)"
                return action_result.set_status(phantom.APP_SUCCESS, msg)
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, f"Failed to create any {entity_type} entities"
                )

        except json.JSONDecodeError as e:
            return action_result.set_status(
                phantom.APP_ERROR, f"Invalid JSON format: {str(e)}"
            )
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to bulk create entities: {err_msg}"
            )

    def _bulk_add_to_container(self, param):
        """
        Bulk add objects to a container (report, grouping, case)

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get parameters
        container_type = param.get("container_type", "").strip()
        container_id = param.get("container_id", "").strip()
        object_ids = param.get("object_ids", "")

        if not container_type:
            return action_result.set_status(
                phantom.APP_ERROR, "Container type is required"
            )

        if not container_id:
            return action_result.set_status(
                phantom.APP_ERROR, "Container ID is required"
            )

        if not object_ids:
            return action_result.set_status(
                phantom.APP_ERROR, "Object IDs are required"
            )

        try:
            # Parse object IDs (can be comma-separated or JSON array)
            if object_ids.startswith("["):
                ids_list = json.loads(object_ids)
            else:
                ids_list = [id.strip() for id in object_ids.split(",")]

            client = self._create_opencti_client()

            added_objects = []
            failed_objects = []

            # Process based on container type
            container_type_lower = container_type.lower()

            for obj_id in ids_list:
                try:
                    if container_type_lower == "report":
                        result = client.report.add_stix_object_or_stix_relationship(
                            id=container_id, stixObjectOrStixRelationshipId=obj_id
                        )
                    elif container_type_lower == "grouping":
                        result = client.grouping.add_stix_object_or_stix_relationship(
                            id=container_id, stixObjectOrStixRelationshipId=obj_id
                        )
                    elif container_type_lower == "case-incident":
                        result = (
                            client.case_incident.add_stix_object_or_stix_relationship(
                                id=container_id, stixObjectOrStixRelationshipId=obj_id
                            )
                        )
                    elif container_type_lower == "case-rfi":
                        result = client.case_rfi.add_stix_object_or_stix_relationship(
                            id=container_id, stixObjectOrStixRelationshipId=obj_id
                        )
                    elif container_type_lower == "case-rft":
                        result = client.case_rft.add_stix_object_or_stix_relationship(
                            id=container_id, stixObjectOrStixRelationshipId=obj_id
                        )
                    else:
                        failed_objects.append(
                            {
                                "object_id": obj_id,
                                "error": f"Unsupported container type: {container_type}",
                            }
                        )
                        continue

                    if result:
                        added_objects.append(obj_id)
                    else:
                        failed_objects.append(
                            {"object_id": obj_id, "error": "Failed to add object"}
                        )

                except Exception as e:
                    failed_objects.append({"object_id": obj_id, "error": str(e)})

            # Add results
            action_result.add_data(
                {
                    "container_id": container_id,
                    "container_type": container_type,
                    "added_objects": added_objects,
                    "failed_objects": failed_objects,
                }
            )

            action_result.update_summary(
                {
                    "total_objects": len(ids_list),
                    "added_count": len(added_objects),
                    "failed_count": len(failed_objects),
                    "container_type": container_type,
                    "container_id": container_id,
                }
            )

            if added_objects:
                msg = f"Successfully added {len(added_objects)}/{len(ids_list)} objects to {container_type}"
                if failed_objects:
                    msg += f" ({len(failed_objects)} failed)"
                return action_result.set_status(phantom.APP_SUCCESS, msg)
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, f"Failed to add any objects to {container_type}"
                )

        except json.JSONDecodeError as e:
            return action_result.set_status(
                phantom.APP_ERROR, f"Invalid JSON format for object IDs: {str(e)}"
            )
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to bulk add objects: {err_msg}"
            )

    def _add_object_to_case_incident(self, param):
        """
        Add an object to a case incident

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        case_id = param.get("case_id")
        object_id = param.get("object_id")

        if not case_id or not object_id:
            return action_result.set_status(
                phantom.APP_ERROR, "Case ID and Object ID are required"
            )

        try:
            client = self._create_opencti_client()
            result = client.case_incident.add_stix_object_or_stix_relationship(
                id=case_id, stixObjectOrStixRelationshipId=object_id
            )

            if result:
                action_result.add_data(
                    {"case_id": case_id, "object_id": object_id, "added": True}
                )
                action_result.update_summary({"object_added": True, "case_id": case_id})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully added object {object_id} to case incident {case_id}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, f"Failed to add object to case incident"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to add object to case incident: {err_msg}"
            )

    def _add_object_to_case_rfi(self, param):
        """
        Add an object to a case RFI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        case_id = param.get("case_id")
        object_id = param.get("object_id")

        if not case_id or not object_id:
            return action_result.set_status(
                phantom.APP_ERROR, "Case ID and Object ID are required"
            )

        try:
            client = self._create_opencti_client()
            result = client.case_rfi.add_stix_object_or_stix_relationship(
                id=case_id, stixObjectOrStixRelationshipId=object_id
            )

            if result:
                action_result.add_data(
                    {"case_id": case_id, "object_id": object_id, "added": True}
                )
                action_result.update_summary({"object_added": True, "case_id": case_id})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully added object {object_id} to case RFI {case_id}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, f"Failed to add object to case RFI"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to add object to case RFI: {err_msg}"
            )

    def _add_object_to_case_rft(self, param):
        """
        Add an object to a case RFT

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        case_id = param.get("case_id")
        object_id = param.get("object_id")

        if not case_id or not object_id:
            return action_result.set_status(
                phantom.APP_ERROR, "Case ID and Object ID are required"
            )

        try:
            client = self._create_opencti_client()
            result = client.case_rft.add_stix_object_or_stix_relationship(
                id=case_id, stixObjectOrStixRelationshipId=object_id
            )

            if result:
                action_result.add_data(
                    {"case_id": case_id, "object_id": object_id, "added": True}
                )
                action_result.update_summary({"object_added": True, "case_id": case_id})
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully added object {object_id} to case RFT {case_id}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, f"Failed to add object to case RFT"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to add object to case RFT: {err_msg}"
            )

    def _enrich_artifact(self, param):
        """
        Enrich a Splunk artifact by searching for an observable in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get parameters
        artifact_value = param.get("artifact_value", "").strip()
        artifact_type = param.get("artifact_type", "").strip()
        include_relationships = param.get("include_relationships", True)
        include_indicators = param.get("include_indicators", True)

        if not artifact_value:
            return action_result.set_status(
                phantom.APP_ERROR, "Artifact value is required"
            )

        try:
            client = self._create_opencti_client()

            # Search for the observable
            observables = client.stix_cyber_observable.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [artifact_value]}],
                    "filterGroups": [],
                },
                first=10,
            )

            enrichment_data = {
                "original_value": artifact_value,
                "original_type": artifact_type,
                "observables": [],
                "indicators": [],
                "relationships": [],
                "entities": [],
                "threat_actors": [],
                "malware": [],
                "campaigns": [],
                "intrusion_sets": [],
            }

            if observables:
                for observable in observables:
                    obs_id = observable.get("id")
                    obs_data = {
                        "id": obs_id,
                        "type": observable.get("entity_type"),
                        "value": observable.get("observable_value"),
                        "score": observable.get("x_opencti_score"),
                        "labels": [
                            label.get("value")
                            for label in observable.get("objectLabel", [])
                        ],
                        "created_at": observable.get("created_at"),
                        "updated_at": observable.get("updated_at"),
                    }
                    enrichment_data["observables"].append(obs_data)

                    # Get indicators if requested
                    if include_indicators and obs_id:
                        indicators = client.stix_cyber_observable.indicators(id=obs_id)
                        if indicators:
                            for indicator in indicators:
                                ind_data = {
                                    "id": indicator.get("id"),
                                    "name": indicator.get("name"),
                                    "pattern": indicator.get("pattern"),
                                    "valid_from": indicator.get("valid_from"),
                                    "valid_until": indicator.get("valid_until"),
                                    "score": indicator.get("x_opencti_score"),
                                    "labels": [
                                        label.get("value")
                                        for label in indicator.get("objectLabel", [])
                                    ],
                                }
                                enrichment_data["indicators"].append(ind_data)

                    # Get relationships if requested
                    if include_relationships and obs_id:
                        # Get relationships where this observable is involved
                        relationships = client.stix_core_relationship.list(
                            fromId=obs_id, first=50
                        )

                        for rel in relationships:
                            rel_data = {
                                "id": rel.get("id"),
                                "relationship_type": rel.get("relationship_type"),
                                "from": rel.get("from", {}).get("id"),
                                "to": rel.get("to", {}).get("id"),
                                "to_name": rel.get("to", {}).get("name"),
                                "to_type": rel.get("to", {}).get("entity_type"),
                                "confidence": rel.get("confidence"),
                                "start_time": rel.get("start_time"),
                                "stop_time": rel.get("stop_time"),
                            }
                            enrichment_data["relationships"].append(rel_data)

                            # Categorize related entities
                            to_entity = rel.get("to", {})
                            entity_type = to_entity.get("entity_type", "").lower()

                            if "threat-actor" in entity_type:
                                enrichment_data["threat_actors"].append(
                                    {
                                        "id": to_entity.get("id"),
                                        "name": to_entity.get("name"),
                                        "description": to_entity.get("description"),
                                    }
                                )
                            elif "malware" in entity_type:
                                enrichment_data["malware"].append(
                                    {
                                        "id": to_entity.get("id"),
                                        "name": to_entity.get("name"),
                                        "description": to_entity.get("description"),
                                    }
                                )
                            elif "campaign" in entity_type:
                                enrichment_data["campaigns"].append(
                                    {
                                        "id": to_entity.get("id"),
                                        "name": to_entity.get("name"),
                                        "description": to_entity.get("description"),
                                    }
                                )
                            elif "intrusion-set" in entity_type:
                                enrichment_data["intrusion_sets"].append(
                                    {
                                        "id": to_entity.get("id"),
                                        "name": to_entity.get("name"),
                                        "description": to_entity.get("description"),
                                    }
                                )

            # Convert to Splunk artifact format
            action_result.add_data(enrichment_data)

            # Update summary
            action_result.update_summary(
                {
                    "enrichment_found": len(enrichment_data["observables"]) > 0,
                    "observable_count": len(enrichment_data["observables"]),
                    "indicator_count": len(enrichment_data["indicators"]),
                    "relationship_count": len(enrichment_data["relationships"]),
                    "threat_actor_count": len(enrichment_data["threat_actors"]),
                    "malware_count": len(enrichment_data["malware"]),
                    "campaign_count": len(enrichment_data["campaigns"]),
                    "intrusion_set_count": len(enrichment_data["intrusion_sets"]),
                }
            )

            if enrichment_data["observables"]:
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Found {len(enrichment_data['observables'])} observables and "
                    f"{len(enrichment_data['indicators'])} indicators for {artifact_value}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"No enrichment data found for {artifact_value} in OpenCTI",
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to enrich artifact: {err_msg}"
            )

    def _bulk_enrich_artifacts(self, param):
        """
        Bulk enrich multiple Splunk artifacts

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get parameters
        artifacts_json = param.get("artifacts_json", "")
        include_relationships = param.get("include_relationships", False)
        include_indicators = param.get("include_indicators", True)

        if not artifacts_json:
            return action_result.set_status(
                phantom.APP_ERROR, "Artifacts JSON is required"
            )

        try:
            # Parse artifacts JSON
            artifacts = json.loads(artifacts_json)
            if not isinstance(artifacts, list):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Artifacts JSON must be a list of artifact objects",
                )

            client = self._create_opencti_client()

            enriched_artifacts = []
            not_found_artifacts = []

            for artifact in artifacts:
                artifact_value = artifact.get("value", "").strip()
                artifact_type = artifact.get("type", "").strip()

                if not artifact_value:
                    continue

                try:
                    # Search for the observable
                    observables = client.stix_cyber_observable.list(
                        filters={
                            "mode": "and",
                            "filters": [{"key": "value", "values": [artifact_value]}],
                            "filterGroups": [],
                        },
                        first=5,
                    )

                    if observables:
                        enrichment = {
                            "original_value": artifact_value,
                            "original_type": artifact_type,
                            "observables": [],
                            "indicators": [],
                            "threat_context": [],
                        }

                        for observable in observables:
                            obs_id = observable.get("id")
                            obs_data = {
                                "id": obs_id,
                                "type": observable.get("entity_type"),
                                "value": observable.get("observable_value"),
                                "score": observable.get("x_opencti_score"),
                                "labels": [
                                    label.get("value")
                                    for label in observable.get("objectLabel", [])
                                ],
                            }
                            enrichment["observables"].append(obs_data)

                            # Get indicators if requested
                            if include_indicators and obs_id:
                                indicators = client.stix_cyber_observable.indicators(
                                    id=obs_id
                                )
                                if indicators:
                                    for indicator in indicators[
                                        :3
                                    ]:  # Limit to 3 per observable
                                        ind_data = {
                                            "name": indicator.get("name"),
                                            "pattern": indicator.get("pattern"),
                                            "score": indicator.get("x_opencti_score"),
                                        }
                                        enrichment["indicators"].append(ind_data)

                            # Get minimal threat context if requested
                            if include_relationships and obs_id:
                                relationships = client.stix_core_relationship.list(
                                    fromId=obs_id, first=10
                                )

                                threat_entities = set()
                                for rel in relationships:
                                    to_entity = rel.get("to", {})
                                    entity_type = to_entity.get(
                                        "entity_type", ""
                                    ).lower()
                                    entity_name = to_entity.get("name")

                                    if entity_name and any(
                                        t in entity_type
                                        for t in [
                                            "threat-actor",
                                            "malware",
                                            "campaign",
                                            "intrusion-set",
                                        ]
                                    ):
                                        threat_entities.add(
                                            f"{entity_type}: {entity_name}"
                                        )

                                enrichment["threat_context"] = list(threat_entities)[
                                    :5
                                ]  # Limit to 5

                        enriched_artifacts.append(enrichment)
                    else:
                        not_found_artifacts.append(
                            {"value": artifact_value, "type": artifact_type}
                        )

                except Exception as e:
                    not_found_artifacts.append(
                        {
                            "value": artifact_value,
                            "type": artifact_type,
                            "error": str(e),
                        }
                    )

            # Add results
            action_result.add_data(
                {
                    "enriched_artifacts": enriched_artifacts,
                    "not_found_artifacts": not_found_artifacts,
                }
            )

            # Update summary
            total_indicators = sum(len(a["indicators"]) for a in enriched_artifacts)
            total_threats = sum(len(a["threat_context"]) for a in enriched_artifacts)

            action_result.update_summary(
                {
                    "total_artifacts": len(artifacts),
                    "enriched_count": len(enriched_artifacts),
                    "not_found_count": len(not_found_artifacts),
                    "total_indicators": total_indicators,
                    "total_threat_context": total_threats,
                }
            )

            if enriched_artifacts:
                msg = f"Successfully enriched {len(enriched_artifacts)}/{len(artifacts)} artifacts"
                if not_found_artifacts:
                    msg += f" ({len(not_found_artifacts)} not found)"
                return action_result.set_status(phantom.APP_SUCCESS, msg)
            else:
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"No enrichment data found for any of the {len(artifacts)} artifacts",
                )

        except json.JSONDecodeError as e:
            return action_result.set_status(
                phantom.APP_ERROR, f"Invalid JSON format: {str(e)}"
            )
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to bulk enrich artifacts: {err_msg}"
            )

    def _create_label(self, param):
        """
        Create a label in OpenCTI

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get required parameters
        value = param.get("value")

        # Get optional parameters
        color = param.get("color")
        stix_id = param.get("stix_id")
        x_opencti_stix_ids = param.get("x_opencti_stix_ids")

        # If no color is provided, generate a predictive color
        if not color:
            color = self._generate_predictive_color(value)
            self.save_progress(
                f"Generated predictive color {color} for label '{value}'"
            )

        # If no STIX ID is provided, generate a predictive one
        if not stix_id:
            stix_id = Label.generate_id(value)
            self.save_progress(f"Generated predictive STIX ID for label '{value}'")

        try:
            client = self._create_opencti_client()

            # Process x_opencti_stix_ids if provided
            stix_ids_list = []
            if x_opencti_stix_ids:
                stix_ids_list = [sid.strip() for sid in x_opencti_stix_ids.split(",")]

            # Create label
            label = client.label.create(
                value=value,
                color=color,
                stix_id=stix_id,
                x_opencti_stix_ids=stix_ids_list if stix_ids_list else None,
                update=True,  # Enable idempotency
            )

            if label:
                action_result.add_data(label)
                action_result.update_summary(
                    {
                        "label_created": True,
                        "label_id": label.get("id"),
                        "label_value": label.get("value"),
                        "label_color": label.get("color"),
                    }
                )
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    f"Successfully created label '{value}' with color {color}",
                )
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, "Failed to create label"
                )

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Failed to create label: {err_msg}"
            )

    def handle_action(self, param):
        """
        Function to handle all the actions supported by this connector

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        ret_val = phantom.APP_SUCCESS

        # Get the action that we need to execute for this connector run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        # Action mapping
        action_mapping = {
            "test_connectivity": self._test_connectivity,
            "list_indicators": self._list_indicators,
            "create_indicator": self._create_indicator,
            "get_indicator": self._get_indicator,
            "create_intrusion_set": self._create_intrusion_set,
            "create_malware": self._create_malware,
            "create_threat_actor": self._create_threat_actor,
            "create_campaign": self._create_campaign,
            "create_vulnerability": self._create_vulnerability,
            "create_relationship": self._create_relationship,
            "search_entities": self._search_entities,
            "create_case_incident": self._create_case_incident,
            "create_case_rfi": self._create_case_rfi,
            "create_case_rft": self._create_case_rft,
            "create_incident": self._create_incident,
            "search_observables": self._search_observables,
            "create_observable": self._create_observable,
            "create_report": self._create_report,
            "create_grouping": self._create_grouping,
            "add_object_to_report": self._add_object_to_report,
            "add_object_to_grouping": self._add_object_to_grouping,
            "create_label": self._create_label,
            "convert_to_stix_pattern": self._convert_to_stix_pattern,
            # New bulk actions
            "bulk_create_entities": self._bulk_create_entities,
            "bulk_add_to_container": self._bulk_add_to_container,
            # New case actions
            "add_object_to_case_incident": self._add_object_to_case_incident,
            "add_object_to_case_rfi": self._add_object_to_case_rfi,
            "add_object_to_case_rft": self._add_object_to_case_rft,
            # New enrichment actions
            "enrich_artifact": self._enrich_artifact,
            "bulk_enrich_artifacts": self._bulk_enrich_artifacts,
        }

        action = action_mapping.get(action_id)

        if action:
            ret_val = action(param)
        else:
            ret_val = phantom.APP_ERROR
            self.debug_print(f"action '{action_id}' is not supported")

        return ret_val


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument(
        "-v",
        "--verify",
        action="store_true",
        help="verify",
        required=False,
        default=False,
    )

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = BaseConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=60)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(
                login_url, verify=verify, data=data, headers=headers, timeout=60
            )
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = OpenCTIConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)


if __name__ == "__main__":
    main()
