# --
# File: sep14_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2017-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --
SEP_CONFIG_URL = "url"
SEP_CONFIG_USERNAME = "username"
SEP_CONFIG_PASSWORD = "password"
SEP_CONFIG_VERIFY_SSL = "verify_server_cert"
SEP_ERR_API_UNSUPPORTED_METHOD = "Unsupported method {method}"
SEP_EXCEPTION_OCCURRED = "Exception occurred"
SEP_ERR_SERVER_CONNECTION = "Connection failed"
SEP_ERR_JSON_PARSE = "Unable to parse the response into a dictionary.\nResponse text - {raw_text}"
SEP_ERR_FROM_SERVER = "API failed.\nStatus code: {status}\nDetail: {detail}"
SEP_REST_RESP_OTHER_ERROR_MSG = "Error returned"
SEP_REST_RESP_SUCCESS = 200
SEP_REST_RESP_BAD_REQUEST = 400
SEP_REST_RESP_BAD_REQUEST_MSG = "Parameters are invalid"
SEP_REST_RESP_UNAUTHORIZED = 401
SEP_REST_RESP_UNAUTHORIZED_MSG = "The user that is currently logged on has insufficient rights to execute the web " \
                                 "method, or the user is unauthorized."
SEP_REST_RESP_FORBIDDEN = 403
SEP_REST_RESP_FORBIDDEN_MSG = "Forbidden."
SEP_REST_RESP_NOT_FOUND = 404
SEP_REST_RESP_NOT_FOUND_MSG = "The requested resource was not found."
SEP_REST_RESP_GONE = 410
SEP_REST_RESP_GONE_MSG = "Gone."
SEP_REST_RESP_ERROR_IN_PROCESSING = 500
SEP_REST_RESP_ERROR_IN_PROCESSING_MSG = "The web service encountered an error while processing the web request."
SEP_CONNECTION_TEST_MSG = "Querying endpoint to verify the credentials provided"
SEP_TEST_CONNECTIVITY_FAIL = "Connectivity test failed"
SEP_TEST_CONNECTIVITY_PASS = "Connectivity test succeeded"
SEP_API_URL = "/sepm/api/v1"
SEP_TEST_CONNECTIVITY_ENDPOINT = "/identity/authenticate"
SEP_VERSION_ENDPOINT = "/version"
SEP_LIST_DOMAINS_ENDPOINT = "/domains"
SEP_LIST_GROUPS_ENDPOINT = "/groups"
SEP_LIST_COMPUTER_ENDPOINTS = "/computers"
SEP_GET_STATUS_ENDPOINT = "/command-queue"
SEP_QUARANTINE_ENDPOINT = "/command-queue/quarantine?computer_ids={params}"
SEP_UNQUARANTINE_ENDPOINT = "/command-queue/quarantine?computer_ids={params}&undo=true"
SEP_FINGERPRINTS_ENDPOINT = "/policy-objects/fingerprints"
SEP_FINGERPRINT_ENDPOINT = "/policy-objects/fingerprints/{fingerprint_id}"
SEP_BLOCK_FILE_ENDPOINT = "/groups/{group_id}/system-lockdown/fingerprints/{fingerprint_id}"
SEP_SCAN_ENDPOINT = "/command-queue/eoc?computer_ids={computer_id}"
SEP_SCAN_ENDPOINT_PAYLOAD = "<EOC creator='Phantom' version='1.1' id='1'><DataSource name='Third-Party Provider' " \
                            "id='1' version='1.0'/><ScanType>{scan_type}</ScanType>" \
                            "<Threat category='' type='' severity='' " \
                            "time='{curr_time}'><Description>{scan_description}" \
                            "</Description><Attacker></Attacker></Threat><Activity></Activity>" \
                            "</EOC>"
SEP_PARAM_NOT_SPECIFIED = "Neither {0} nor {1} specified. Please specify at least one of them"
SEP_IP_HOSTNAME_VALIDATION_ERROR = "Parameter validation failed for 'ip_hostname' field"
SEP_DEVICE_NOT_FOUND = "Device not found to {action}"
SEP_BLOCK_HASH_GET_DETAILS_ERROR = "Error while getting details of fingerprint file with name: {name}"
SEP_BLOCK_HASH_GET_ID_ERROR = "Error while getting ID of fingerprint file"
SEL_BLACKLIST_GROUP_ID_NOT_FOUND = "Group ID provided is not found. Please enter a valid group ID"
SEP_HASH_FAILED_VALIDATION = "Parameter {param} failed validation"
SEP_HASH_ADDED_TO_FILE = "Hash added to the fingerprint file"
SEP_HASH_REMOVED_FROM_FILE = "Hash removed from the fingerprint file"
SEP_HASH_ALREADY_PRESENT = "Hash already present in the fingerprint file, not updating"
SEP_HASH_NOT_PRESENT = "Hash not present in the fingerprint file, not updating"
SEP_PARAM_GROUP_ID = "group_id"
SEP_PARAM_HASH = "hash"
SEP_PARAM_COMPUTER_ID = "id"
SEP_PARAM_IP_HOSTNAME = "ip_hostname"
SEP_PARAM_DOMAIN = "admin_domain"
SEP_PARAM_TIMEOUT = "timeout"
SEP_INVALID_TIMEOUT = "Invalid Timeout"
SEP_INVALID_DOMAIN = "Invalid Domain"
SEP_INVALID_IP_HOSTNAME = "Invalid IP/Hostname"
SEP_PARAM_SCAN_TYPE = "type"
SEP_VALIDATE_VERSION_FAILED = "Product version validation failed."
SEP_JSON_VERSION = "version"
SEP_UNABLE_TO_GET_VERSION = "Unable to get version from the device"
SEP_VERSION_VALIDATED = "Version validation done"
