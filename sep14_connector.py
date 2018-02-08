# --
# File: sep14_connector.py
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

# Standard library imports
import json
import datetime
import re
import time
import requests
import xmltodict
from bs4 import BeautifulSoup

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
import sep14_consts as consts

COMMAND_STATE_DESC = {
    "0": "INITIAL",
    "1": "RECEIVED",
    "2": "IN_PROGRESS",
    "3": "COMPLETED",
    "4": "REJECTED",
    "5": "CANCELED",
    "6": "ERROR"
}

COMMAND_SUB_STATE_DESC = {
    '-1': 'Unknown', '0': 'Success', '1': 'Client did not execute the command'
}

# Dictionary that maps each error code with its corresponding message
ERROR_RESPONSE_DICT = {
    consts.SEP_REST_RESP_UNAUTHORIZED: consts.SEP_REST_RESP_UNAUTHORIZED_MSG,
    consts.SEP_REST_RESP_BAD_REQUEST: consts.SEP_REST_RESP_BAD_REQUEST_MSG,
    consts.SEP_REST_RESP_NOT_FOUND: consts.SEP_REST_RESP_NOT_FOUND_MSG,
    consts.SEP_REST_RESP_ERROR_IN_PROCESSING: consts.SEP_REST_RESP_ERROR_IN_PROCESSING_MSG,
    consts.SEP_REST_RESP_FORBIDDEN: consts.SEP_REST_RESP_FORBIDDEN_MSG,
    consts.SEP_REST_RESP_GONE: consts.SEP_REST_RESP_GONE_MSG
}


class Sep14Connector(BaseConnector):
    """ This is an AppConnector class that inherits the BaseConnector class. It implements various actions supported by
    sep14 and helper methods required to run the actions.
    """

    def __init__(self):

        # Calling the BaseConnector's init function
        super(Sep14Connector, self).__init__()
        self._url = None
        self._username = None
        self._password = None
        self._verify_server_cert = None
        self._state = None
        self._token = None

        return

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        config = self.get_config()
        self._url = config[consts.SEP_CONFIG_URL]
        self._username = config[consts.SEP_CONFIG_USERNAME]
        self._password = config[consts.SEP_CONFIG_PASSWORD]
        self._verify_server_cert = config.get(consts.SEP_CONFIG_VERIFY_SSL, False)
        self._state = self.load_state()
        if self._state:
            self._token = self._state.get('token')

        # Custom validation for MD5
        self.set_validator("md5", None)

        return phantom.APP_SUCCESS

    def _generate_api_token(self, action_result):
        """Generate new token based on the credentials provided.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        authorization = {
            "username": self._username,
            "password": self._password
        }
        response_status, response = self._make_rest_call(consts.SEP_TEST_CONNECTIVITY_ENDPOINT, action_result,
                                                         data=json.dumps(authorization), timeout=30, method="post")

        if phantom.is_fail(response_status):
            self._state['token'] = None
            return action_result.get_status()

        token = response.get("token")
        if not token:
            self.debug_print("Failed to generate token")
            return action_result.set_status(phantom.APP_ERROR, "Failed to generate token")

        self._state['token'] = self._token = token

        return phantom.APP_SUCCESS

    def _make_rest_call_abstract(self, endpoint, action_result, headers=None, data=None, params=None, method="get",
                                 timeout=None):
        """This method generates a new token if it is not available or if the existing token has expired
        and makes the call using _make_rest_call method.

        :param endpoint: REST endpoint
        :param action_result: object of ActionResult class
        :param headers: requests headers
        :param data: request body
        :param params: request params
        :param method: GET/POST/PUT/DELETE (Default method will be 'GET')
        :param timeout: request timeout
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message) and API response
        """

        # Use this object for _make_rest_call
        # Final status of action_result will be determined after retry, in case the token is expired
        intermediate_action_result = ActionResult()
        response_data = None

        # Generate new token if not available
        if not self._token:
            ret_code = self._generate_api_token(action_result)
            if phantom.is_fail(ret_code):
                return action_result.get_status(), response_data

        if headers:
            headers.update({"Authorization": "Bearer {}".format(self._token)})
        else:
            headers = {"Authorization": "Bearer {}".format(self._token)}

        # Make call
        rest_ret_code, response_data = self._make_rest_call(endpoint, intermediate_action_result, headers=headers,
                                                            params=params, data=data, method=method, timeout=timeout)

        # Regenerating a new token if expired
        if str(consts.SEP_REST_RESP_UNAUTHORIZED) in str(intermediate_action_result.get_message()):
            ret_code = self._generate_api_token(action_result)

            if phantom.is_fail(ret_code):
                return action_result.get_status(), response_data

            headers = {"Authorization": "Bearer {}".format(self._token)}

            rest_ret_code, response_data = self._make_rest_call(endpoint, intermediate_action_result, headers=headers,
                                                                params=params, data=data, method=method)

        # Assigning intermediate action_result to action_result, since no further invocation required
        if phantom.is_fail(rest_ret_code):
            action_result.set_status(rest_ret_code, intermediate_action_result.get_message())
            return action_result.get_status(), response_data

        return phantom.APP_SUCCESS, response_data

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get",
                        timeout=None):
        """ Function that makes the REST call to the device. It is a generic function that can be called from various
        action handlers.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters if method is get
        :param data: request body
        :param method: GET/POST/PUT/DELETE ( Default method will be 'GET' )
        :param timeout: request timeout
        :return: status success/failure(along with appropriate message), response obtained by making an API call
        """

        response_data = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            self.debug_print(consts.SEP_ERR_API_UNSUPPORTED_METHOD.format(method=method))
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(
                phantom.APP_ERROR, consts.SEP_ERR_API_UNSUPPORTED_METHOD.format(method=method)), response_data
        except Exception as e:
            self.debug_print(consts.SEP_EXCEPTION_OCCURRED, e)
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.SEP_EXCEPTION_OCCURRED, e), response_data

        if headers:
            if not headers.get("Content-Type"):
                headers.update({"Content-Type": "application/json"})
        else:
            headers = {"Content-Type": "application/json"}

        # Make the call
        try:
            response = request_func("{}{}{}".format(self._url, consts.SEP_API_URL, endpoint), params=params,
                                    data=data, headers=headers, verify=self._verify_server_cert,
                                    timeout=timeout)

            # store the r_text in debug data, it will get dumped in the logs if an error occurs
            if hasattr(action_result, 'add_debug_data'):
                if response is not None:
                    action_result.add_debug_data({'r_status_code': response.status_code})
                    action_result.add_debug_data({'r_text': response.text})
                    action_result.add_debug_data({'r_headers': response.headers})
                else:
                    action_result.add_debug_data({'r_text': 'r is None'})

        except Exception as e:
            self.debug_print(consts.SEP_ERR_SERVER_CONNECTION, e)
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.SEP_ERR_SERVER_CONNECTION, e), response_data

        # Try parsing the json
        try:
            content_type = response.headers.get('content-type', "")
            if 'json' in content_type:
                response_data = response.json()
            elif 'html' in content_type:
                response_data = self._process_html_response(response)
            else:
                response_data = response.text
        except Exception as e:
            # r.text is guaranteed to be NON None, it will be empty, but not None
            msg_string = consts.SEP_ERR_JSON_PARSE.format(raw_text=response.text)
            self.debug_print(msg_string, e)
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, msg_string, e), response_data

        if response.status_code in ERROR_RESPONSE_DICT:
            message = ERROR_RESPONSE_DICT[response.status_code]

            # overriding message if available in response
            if isinstance(response_data, dict):
                message = response_data.get("error_description", response_data.get("errorMessage", response_data.get(
                    "message", message)))

            self.debug_print(consts.SEP_ERR_FROM_SERVER.format(status=response.status_code,
                                                               detail=message))
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.SEP_ERR_FROM_SERVER,
                                            status=response.status_code, detail=message), response_data

        # In case of success scenario
        if response.status_code == consts.SEP_REST_RESP_SUCCESS:
            return phantom.APP_SUCCESS, response_data

        # If response code is unknown
        message = consts.SEP_REST_RESP_OTHER_ERROR_MSG

        # overriding message if available in response
        if isinstance(response_data, dict):
            message = response_data.get("error_description", response_data.get("errorMessage", response_data.get(
                "message", message)))

        # If response code is unknown
        self.debug_print(consts.SEP_ERR_FROM_SERVER.format(
            status=response.status_code, detail=message))
        # All other response codes from REST call
        # Set the action_result status to error, the handler function will most probably return as is
        return action_result.set_status(phantom.APP_ERROR, consts.SEP_ERR_FROM_SERVER,
                                        status=response.status_code,
                                        detail=message), response_data

    def _get_endpoint_details(self, action_result):
        """ Helper function to get endpoint details.

        :param action_result: object of ActionResult class
        :return status(True/False), endpoint details list
        """

        # Getting endpoint details
        status, endpoint_details = self._make_rest_call_abstract(consts.SEP_LIST_COMPUTER_ENDPOINTS, action_result)

        # Something went wrong while getting endpoint details
        if phantom.is_fail(status):
            self.debug_print("Error while getting endpoint details")
            return action_result.set_status(phantom.APP_ERROR, "Error while getting endpoint details"), None

        return phantom.APP_SUCCESS, endpoint_details.get("content", [])

    def _get_endpoint_id_from_ip_hostname(self, action_result, value_to_search, search_key_field):
        """ Helper function to get endpoint ID from given IP or hostname.

        :param action_result: Object of ActionResult class
        :param value_to_search: Given ID/IP or hostname list
        :param search_key_field: Search key field list
        :return Status (True/False) and Endpoint ID/None
        """

        computer_ids = list()

        # Getting endpoint details
        status, endpoint_list = self._get_endpoint_details(action_result)

        # Something went wrong while getting endpoint details
        if phantom.is_fail(status):
            return action_result.get_status(), None

        # Checking if endpoint is already in quarantine state
        for index, search_key in enumerate(search_key_field):
            id_found = False
            for endpoint in endpoint_list:
                # If key to search has a list, then value will be searched in the list
                if isinstance(endpoint[search_key], list):
                    if value_to_search[index] not in endpoint[search_key]:
                        continue
                # if value is string, then value will be matched exactly to value of key in response
                elif isinstance(endpoint[search_key], basestring) and endpoint[search_key] != value_to_search[index]:
                    continue

                # If computer ID is not provided, then value of computer ID will be obtained based on provided
                # IP address or hostname
                if endpoint["uniqueId"]:
                    id_found = True
                    computer_ids.append(endpoint["uniqueId"])
                break

            # If computer ID not found
            if not id_found:
                self.debug_print(consts.SEP_DEVICE_NOT_FOUND.format(action="scan"))
                return action_result.set_status(phantom.APP_ERROR, "{} {}".format(
                    consts.SEP_DEVICE_NOT_FOUND.format(action="scan"), value_to_search[index])), None

        return phantom.APP_SUCCESS, computer_ids

    def _get_groups(self, action_result):
        """ Helper function to get details of all groups.

        :param action_result: object of ActionResult class
        :return status(Success/Failure), list of groups
        """

        # List containing all groups
        group_details = list()
        params = {'pageIndex': 1}

        # Paginating data to get details of all groups
        while True:
            # Getting details of groups
            response_status, response_data = self._make_rest_call_abstract(consts.SEP_LIST_GROUPS_ENDPOINT,
                                                                           action_result, params=params)

            # Something went wrong while getting group details
            if phantom.is_fail(response_status):
                self.debug_print("Error while getting group details")
                return action_result.get_status(), None

            # Adding group contents
            group_details += response_data['content']

            # Break on last page
            if response_data['lastPage']:
                break

            # Incrementing page index to next set of groups
            params['pageIndex'] += 1

        return phantom.APP_SUCCESS, group_details

    def _get_domain_id_by_name(self, action_result, domain):
        """ Helper function to get domain id by domain name.

        :param action_result: Object of ActionResult class
        :param domain: domain name
        :return: domain id
        """

        response_status, response_data = self._make_rest_call_abstract(consts.SEP_LIST_DOMAINS_ENDPOINT, action_result)

        if phantom.is_fail(response_status):
            self.debug_print("Error while getting domain details")
            return action_result.get_status()

        for item in response_data:
            if item['name'].lower() == domain.lower():
                return item['id']

        return None

    def _get_fingerprint_file_info(self, action_result, fingerprint_filename):
        """ Helper function to get fingerprint file information based on file name.

        :param action_result: object of ActionResult class
        :param fingerprint_filename: Name of fingerprint file
        :return status (Success, Failure), File details/None
        """

        # Executing REST API call to get already blocked hashes in file fingerprint list
        resp_status, file_details = self._make_rest_call_abstract(consts.SEP_FINGERPRINTS_ENDPOINT,
                                                                  action_result,
                                                                  params={"name": fingerprint_filename},
                                                                  method="get")

        # Something went wrong while getting details of fingerprint file
        if phantom.is_fail(resp_status):

            # If fingerprint file is not present, its not an error condition. It indicates that no files are blocked.
            if str(file_details.get("errorCode")) != "410" and not str(
                    file_details.get("errorMessage")).__contains__("do not exist"):
                self.debug_print(consts.SEP_BLOCK_HASH_GET_DETAILS_ERROR.format(
                    name=fingerprint_filename
                ))
                return action_result.get_status(), None

        return phantom.APP_SUCCESS, file_details

    def _update_blocked_hash_list(self, input_hash_list, blocked_hash_list):
        """ Helper function to check if hash value is present in fingerprint file list.

        :param input_hash_list: List of hash values provided by user to block or unblock
        :param blocked_hash_list: List of hash values present in fingerprint file
        :return status (Success/Failure), list of objects of ActionResult class containing status of each hash
            value in the input_hash_list, updated blocked hash list and object having each hash's status
        """

        # List to store action_result for each input hash
        ar_hash_list = []
        # Object containing status of each hash value (blocked/unblocked, already blocked/already unblocked, failed hash
        # validation)
        hash_value_status = dict()
        # Iterating over input hash values
        for hash_value in input_hash_list:
            ar_curr_hash = ActionResult({consts.SEP_PARAM_HASH: hash_value})
            ar_hash_list.append(ar_curr_hash)
            # If given hash is not a valid MD5 hash
            if not phantom.is_md5(hash_value):
                # Increment value if hash given in the list is invalid
                hash_value_status["invalid_hashes"] = hash_value_status.get("invalid_hashes", 0) + 1
                ar_curr_hash.set_status(phantom.APP_ERROR, consts.SEP_HASH_FAILED_VALIDATION.format(
                    param=consts.SEP_PARAM_HASH
                ))
                continue

            # If action is to block given hashes
            if self.get_action_identifier() == "block_hash":
                # If hash value is not present in fingerprint file
                if hash_value.upper() not in blocked_hash_list:
                    # Increment value if hash given in the list needs to be added in the fingerprint
                    hash_value_status["hashes_blocked"] = hash_value_status.get("hashes_blocked", 0) + 1
                    blocked_hash_list.append(hash_value)
                    ar_curr_hash.set_status(phantom.APP_SUCCESS, consts.SEP_HASH_ADDED_TO_FILE)
                # If hash value is already present in fingerprint file
                else:
                    # Increment value if hash given in the list is already blocked
                    hash_value_status["hashes_already_blocked"] = hash_value_status.get("hashes_already_blocked", 0) + 1
                    ar_curr_hash.set_status(phantom.APP_SUCCESS, consts.SEP_HASH_ALREADY_PRESENT)
            # If action is to unblock given hashes
            else:
                # If hash value is present in fingerprint file
                if hash_value.upper() in blocked_hash_list:
                    # Increment value if hash given in the list needs to be removed from the fingerprint
                    hash_value_status["hashes_unblocked"] = hash_value_status.get("hashes_unblocked", 0) + 1
                    blocked_hash_list.remove(hash_value.upper())
                    ar_curr_hash.set_status(phantom.APP_SUCCESS, consts.SEP_HASH_REMOVED_FROM_FILE)
                # If hash value is already present in fingerprint file
                else:
                    # Increment value if hash given in the list is already unblocked
                    hash_value_status["hashes_already_unblocked"] = hash_value_status.get(
                        "hashes_already_unblocked", 0) + 1
                    ar_curr_hash.set_status(phantom.APP_SUCCESS, consts.SEP_HASH_NOT_PRESENT)

        return ar_hash_list, blocked_hash_list, hash_value_status

    def _process_html_response(self, response):
        """ This function is used to parse html response.

        :param response: actual response
        :return: error message
        """

        # An html response, treat it like an error

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines).encode('utf-8').strip()
        except:
            error_text = "Cannot parse error details"

        message = "{0}\n".format(error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        message = {"errorMessage": message}

        return message

    def _list_domains(self, param):
        """This function is used to list all domains.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        response_status, response_data = self._make_rest_call_abstract(consts.SEP_LIST_DOMAINS_ENDPOINT, action_result)

        if phantom.is_fail(response_status):
            return action_result.get_status()

        for item in response_data:
            action_result.add_data(item)

        summary_data['total_domains'] = len(response_data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_groups(self, param):
        """This function is used to list all the groups configured on the device.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting list of groups to get domain ID of the group ID provided
        status, group_list = self._get_groups(action_result)

        # Something went wrong while getting list of groups
        if phantom.is_fail(status):
            return action_result.get_status()

        for group_details in group_list:
            action_result.add_data(group_details)

        summary_data['total_groups'] = len(group_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_status(self, param):
        """This function is used to get the details of a command status.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})
        endpoint_status_details = list()
        command_id = param['id']

        params = {'pageIndex': 1}

        while True:
            response_status, response_data = self._make_rest_call_abstract("{}/{}".format(
                consts.SEP_GET_STATUS_ENDPOINT, command_id), action_result, params=params)

            if phantom.is_fail(response_status):
                return action_result.get_status()

            for content in response_data['content']:
                endpoint_status_details.append("{}- {}".format(content["computerName"],
                                                               COMMAND_STATE_DESC.get(str(content["stateId"]), "NA")))
                self.send_progress(
                    'Command State: {0}({1}), Sub-State: {2}({3})'.format(
                        content["stateId"], COMMAND_STATE_DESC.get(str(content["stateId"]), "NA"),
                        content["subStateId"], COMMAND_SUB_STATE_DESC.get(str(content["subStateId"]), 'NA')
                    )
                )

                action_result.add_data(content)

            if response_data['lastPage']:
                break

            params['pageIndex'] += 1

        summary_data["command_state"] = ", ".join(endpoint_status_details)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _quarantine_device(self, param):
        """ Function to quarantine an endpoint provided as input parameter.

        :param param: Object containing group ID and endpoint ID
        :return status (Success / Failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})
        search_key_field = list()

        # Getting computer IDs to quarantine
        computer_id = param.get(consts.SEP_PARAM_COMPUTER_ID)
        # Getting IP/Hostname given to quarantine
        ip_hostname = param.get(consts.SEP_PARAM_IP_HOSTNAME)

        # If none of the parameters are specified
        if not computer_id and not ip_hostname:
            self.debug_print(consts.SEP_PARAM_NOT_SPECIFIED.format(
                consts.SEP_PARAM_COMPUTER_ID, consts.SEP_PARAM_IP_HOSTNAME
            ))
            return action_result.set_status(phantom.APP_ERROR, consts.SEP_PARAM_NOT_SPECIFIED.format(
                consts.SEP_PARAM_COMPUTER_ID, consts.SEP_PARAM_IP_HOSTNAME
            ))
        # If computer_id is specified, then ip_hostname parameter will be ignored
        elif computer_id:
            search_key_field.append("uniqueId")
            value_to_search = [x.strip() for x in computer_id.split(',')]
        else:
            value_to_search = ip_hostname = [x.strip() for x in ip_hostname.split(',')]

            for index, item in enumerate(ip_hostname):
                # Checking if given value is an IP address
                if phantom.is_ip(item):
                    search_key_field.append("ipAddresses")
                elif phantom.is_hostname(item):
                    search_key_field.append("computerName")
                else:
                    self.debug_print(consts.SEP_IP_HOSTNAME_VALIDATION_ERROR)
                    return action_result.set_status(phantom.APP_ERROR, consts.SEP_IP_HOSTNAME_VALIDATION_ERROR)

        # Optional parameter
        timeout = param.get(consts.SEP_PARAM_TIMEOUT, 30)

        # Validate timeout
        if not str(timeout).isdigit():
            self.debug_print(consts.SEP_INVALID_TIMEOUT)
            return action_result.set_status(phantom.APP_ERROR, consts.SEP_INVALID_TIMEOUT), None

        # Getting endpoint details
        status, endpoint_list = self._get_endpoint_details(action_result)

        # Something went wrong while getting endpoint details
        if phantom.is_fail(status):
            return action_result.get_status()

        computer_ids = list()
        # Checking if endpoint is already in quarantine state
        for index, search_key in enumerate(search_key_field):
            id_found = False

            for endpoint in endpoint_list:
                # If key to search has a list, then value will be searched in the list
                if isinstance(endpoint[search_key], list):
                    if value_to_search[index] not in endpoint[search_key]:
                        continue
                # if value is string, then value will be matched exactly to value of key in response
                elif isinstance(endpoint[search_key], basestring) and endpoint[search_key] != value_to_search[index]:
                    continue

                # If computer ID is not provided, then value of computer ID will be obtained based on provided
                # IP address or hostname
                if endpoint["uniqueId"]:
                    id_found = True
                    computer_ids.append(endpoint["uniqueId"])
                break

            # If computer ID not found
            if not id_found:
                self.debug_print(consts.SEP_DEVICE_NOT_FOUND.format(action="quarantine"))
                return action_result.set_status(phantom.APP_ERROR, "{message} {computer_id}".format(
                    message=consts.SEP_DEVICE_NOT_FOUND.format(action="quarantine"), computer_id=value_to_search[index]
                ))

        computer_id = ",".join(list(set(computer_ids)))

        # Executing API to quarantine specified endpoint
        response_status, response_data = self._make_rest_call_abstract("{quarantine_api}".format(
            quarantine_api=consts.SEP_QUARANTINE_ENDPOINT.format(
                params=computer_id
            )), action_result, method="post")

        # Something went wrong while quarantining the endpoint(s)
        if phantom.is_fail(response_status):
            return action_result.get_status()

        # Adding response to ActionResult Object
        action_result.add_data(response_data)

        # Providing Command ID in summary
        try:
            summary_data["command_id"] = response_data.pop("commandID_computer")
        except:
            pass

        # Poll for command status
        command_status, state_id_status = self._get_command_status_by_id(
            action_result, summary_data.get("command_id"), timeout
        )
        # Something went wrong
        if phantom.is_fail(command_status):
            return action_result.get_status()

        summary_data["state_id_status"] = state_id_status

        action_result.set_status(phantom.APP_SUCCESS)

    def _unblock_hash(self, param):
        """ This function is used to unblock existing hashes for a group.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})
        domain_id = None

        # Getting mandatory parameters
        group_id = param[consts.SEP_PARAM_GROUP_ID]
        hash_values = param[consts.SEP_PARAM_HASH].replace(" ", "").split(",")

        fingerprint_filename = "phantom_{group_id}".format(group_id=group_id)

        # Getting fingerprint file information
        resp_status, file_details = self._get_fingerprint_file_info(action_result, fingerprint_filename)

        # Something went wrong while getting details of fingerprint file
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        # Getting list of all hashes that are present in fingerprint file
        blocked_hash_list = [hash_value.upper() for hash_value in file_details.get("data", [])]
        # Total number of already blocked hash list
        fingerprint_num_blocked_hash_list = len(blocked_hash_list)

        # Calling a function that will check if given hash values are present in fingerprint or not.
        # This function will remove all hashes provided in hash_values and will return only remaining values that
        # that will be added to the fingerprint file and each hash's status
        ar_hash_list, updated_block_hash_list, hash_value_status = self._update_blocked_hash_list(hash_values,
                                                                                                  blocked_hash_list)

        ar_hash_list = [x.get_dict() for x in ar_hash_list]

        # If any hashes are deleted from the fingerprint file, then only file will be updated
        if len(updated_block_hash_list) != fingerprint_num_blocked_hash_list:
            # If all hashes in a file will be unblocked, then fingerprint file will be deleted
            method = "delete"
            fingerprint_api_data = None
            command_id = file_details.get("id")

            # If some hashes are left blocked in a fingerprint file
            if updated_block_hash_list:
                method = "post"
                # Getting list of groups to get domain ID of the group ID provided
                status, group_list = self._get_groups(action_result)

                # Something went wrong while getting list of groups
                if phantom.is_fail(status):
                    return action_result.get_status()

                # Iterating over group to get details of group whose ID is provided in input parameter
                for group_detail in group_list:
                    if group_detail["id"] != group_id:
                        continue

                    domain_id = group_detail["domain"]["id"]
                    break

                # If no corresponding domain is found for the given group ID
                if not domain_id:
                    self.debug_print(consts.SEL_BLACKLIST_GROUP_ID_NOT_FOUND)
                    return action_result.set_status(phantom.APP_ERROR, consts.SEL_BLACKLIST_GROUP_ID_NOT_FOUND)

                fingerprint_api_data = json.dumps({"hashType": "MD5",
                                                   "name": "phantom_{group_id}".format(group_id=group_id),
                                                   "domainId": domain_id,
                                                   "data": updated_block_hash_list})

            # Execute REST API to either delete or update the fingerprint file after unblocking hashes provided
            response_status, response_data = self._make_rest_call_abstract("{}/{}".format(
                consts.SEP_FINGERPRINTS_ENDPOINT, command_id), action_result, data=fingerprint_api_data, method=method)

            # Something went wrong while updating fingerprint file
            if phantom.is_fail(response_status):
                return action_result.get_status()

        summary_data.update(hash_value_status)
        # Adding domain ID to the fingerprint file details
        file_details["domainId"] = domain_id
        action_result.add_data({"hash_info": ar_hash_list, "fingerprint_file_info": file_details})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _unquarantine_device(self, param):
        """ Function to unquarantine an endpoint provided as input parameter.

        :param param: Object containing group ID and endpoint ID
        :return status (Success / Failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})
        search_key_field = list()

        # Getting computer IDs to quarantine
        computer_id = param.get(consts.SEP_PARAM_COMPUTER_ID)
        # Getting IP/Hostname given to quarantine
        ip_hostname = param.get(consts.SEP_PARAM_IP_HOSTNAME)

        # If none of the parameters are specified
        if not computer_id and not ip_hostname:
            self.debug_print(consts.SEP_PARAM_NOT_SPECIFIED.format(
                consts.SEP_PARAM_COMPUTER_ID, consts.SEP_PARAM_IP_HOSTNAME
            ))
            return action_result.set_status(phantom.APP_ERROR, consts.SEP_PARAM_NOT_SPECIFIED.format(
                consts.SEP_PARAM_COMPUTER_ID, consts.SEP_PARAM_IP_HOSTNAME
            ))
        # If computer_id is specified, then ip_hostname parameter will be ignored
        elif computer_id:
            search_key_field.append("uniqueId")
            value_to_search = [x.strip() for x in computer_id.split(',')]
        else:
            value_to_search = ip_hostname = [x.strip() for x in ip_hostname.split(',')]

            for index, item in enumerate(ip_hostname):
                # Checking if given value is an IP address
                if phantom.is_ip(item):
                    search_key_field.append("ipAddresses")
                elif phantom.is_hostname(item):
                    search_key_field.append("computerName")
                else:
                    self.debug_print(consts.SEP_IP_HOSTNAME_VALIDATION_ERROR)
                    return action_result.set_status(phantom.APP_ERROR, consts.SEP_IP_HOSTNAME_VALIDATION_ERROR)

        # Optional parameter
        timeout = param.get(consts.SEP_PARAM_TIMEOUT, 30)

        # Validate timeout
        if not str(timeout).isdigit():
            self.debug_print(consts.SEP_INVALID_TIMEOUT)
            return action_result.set_status(phantom.APP_ERROR, consts.SEP_INVALID_TIMEOUT), None

        # Getting endpoint details
        status, endpoint_list = self._get_endpoint_details(action_result)

        # Something went wrong while getting endpoint details
        if phantom.is_fail(status):
            return action_result.get_status()

        computer_ids = list()
        # Checking if endpoint is already in quarantine state
        for index, search_key in enumerate(search_key_field):
            id_found = False

            for endpoint in endpoint_list:
                # If key to search has a list, then value will be searched in the list
                if isinstance(endpoint[search_key], list):
                    if value_to_search[index] not in endpoint[search_key]:
                        continue
                # if value is string, then value will be matched exactly to value of key in response
                elif isinstance(endpoint[search_key], basestring) and endpoint[search_key] != value_to_search[index]:
                    continue

                # If computer ID is not provided, then value of computer ID will be obtained based on provided
                # IP address or hostname
                if endpoint["uniqueId"]:
                    id_found = True
                    computer_ids.append(endpoint["uniqueId"])
                break

            # If computer ID not found
            if not id_found:
                self.debug_print(consts.SEP_DEVICE_NOT_FOUND.format(action="unquarantine"))
                return action_result.set_status(phantom.APP_ERROR, "{message} {computer_id}".format(
                    message=consts.SEP_DEVICE_NOT_FOUND.format(action="unquarantine"),
                    computer_id=value_to_search[index]
                ))

        computer_id = ",".join(list(set(computer_ids)))

        # Executing API to quarantine specified endpoint
        response_status, response_data = self._make_rest_call_abstract("{unquarantine_api}".format(
            unquarantine_api=consts.SEP_UNQUARANTINE_ENDPOINT.format(
                params=computer_id
            )), action_result, method="post")

        # Something went wrong while quarantining the endpoint(s)
        if phantom.is_fail(response_status):
            return action_result.get_status()

        # Adding response to ActionResult Object
        action_result.add_data(response_data)

        # Providing Command ID in summary
        try:
            summary_data["command_id"] = response_data.pop("commandID_computer")
        except:
            pass

        # Poll for command status
        command_status, state_id_status = self._get_command_status_by_id(
            action_result, summary_data.get("command_id"), timeout
        )
        # Something went wrong
        if phantom.is_fail(command_status):
            return action_result.get_status()

        summary_data["state_id_status"] = state_id_status

        action_result.set_status(phantom.APP_SUCCESS)

    def _block_hash(self, param):
        """ Function to block file based on given hash values.
        :param param: Object containing hash values, name and description
        :return status (Success/Failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        domain_id = None
        fingerprint_file_id = None

        # Getting parameters to create a fingerprint file and group ID to which fingerprints will be assigned
        group_id = param[consts.SEP_PARAM_GROUP_ID]
        hash_values = param[consts.SEP_PARAM_HASH].replace(" ", "").split(",")

        fingerprint_filename = "phantom_{group_id}".format(group_id=group_id)
        fingerprint_file_desc = "List of applications that are blocked in group having ID " \
                                "{group_id}".format(group_id=group_id)

        # Getting list of groups to get domain ID of the group ID provided
        status, group_list = self._get_groups(action_result)

        # Something went wrong while getting list of groups
        if phantom.is_fail(status):
            return action_result.get_status()

        # Iterating over group to get details of group whose ID is provided in input parameter
        for group_detail in group_list:
            if group_detail["id"] != group_id:
                continue

            domain_id = group_detail["domain"]["id"]
            break

        # If group not found
        if not domain_id:
            self.debug_print(consts.SEL_BLACKLIST_GROUP_ID_NOT_FOUND)
            return action_result.set_status(phantom.APP_ERROR, consts.SEL_BLACKLIST_GROUP_ID_NOT_FOUND)

        # Dictionary containing fingerprint file details
        api_data = {
            "name": str(fingerprint_filename), "domainId": str(domain_id), "hashType": "MD5"
        }

        # If description is provided
        if fingerprint_file_desc:
            api_data["description"] = fingerprint_file_desc

        # Getting fingerprint file information
        resp_status, file_details = self._get_fingerprint_file_info(action_result, fingerprint_filename)

        # Something went wrong while getting details of fingerprint file
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        # Getting list of all hashes that are present in fingerprint file
        blocked_hash_list = [hash_value.upper() for hash_value in file_details.get("data", [])]
        # Total number of already blocked hash list
        fingerprint_num_blocked_hash_list = len(blocked_hash_list)

        # Calling a function that will check if given hash values are present in fingerprint or not
        ar_hash_list, updated_blocked_hash_list, hash_value_status = self._update_blocked_hash_list(hash_values,
                                                                                                    blocked_hash_list)

        ar_hash_list = [x.get_dict() for x in ar_hash_list]

        # If there some new hashes that to be added to fingerprint file
        if len(updated_blocked_hash_list) != fingerprint_num_blocked_hash_list:
            fingerprint_endpoint_url = consts.SEP_FINGERPRINTS_ENDPOINT
            # If fingerprint file is already present
            if file_details.get("id"):
                fingerprint_file_id = file_details["id"]
                fingerprint_endpoint_url = consts.SEP_FINGERPRINT_ENDPOINT.format(
                    fingerprint_id=fingerprint_file_id
                )

            api_data["data"] = updated_blocked_hash_list

            # Executing REST API call to add a blacklist as a file fingerprint list to SEP Manager
            resp_status, file_resp_data = self._make_rest_call_abstract(fingerprint_endpoint_url, action_result,
                                                                        data=json.dumps(api_data), method="post")

            # Something went wrong while adding file fingerprint list to SEP Manager
            if phantom.is_fail(resp_status):
                return action_result.get_status()

            if not fingerprint_file_id:
                # If fingerprint file ID is not found in the response
                if isinstance(file_resp_data, dict) and not file_resp_data.get("id"):
                    self.debug_print(consts.SEP_BLOCK_HASH_GET_ID_ERROR)
                    return action_result.set_status(phantom.APP_ERROR, consts.SEP_BLOCK_HASH_GET_ID_ERROR)

                # Getting file ID of fingerprint list
                fingerprint_file_id = file_resp_data["id"]

            # Executing REST API call to add fingerprint file as blacklist to provided group
            resp_status, blacklist_file_resp_data = self._make_rest_call_abstract(consts.SEP_BLOCK_FILE_ENDPOINT.format(
                group_id=group_id, fingerprint_id=fingerprint_file_id
            ), action_result, method="put")

            # Something went wrong while adding fingerprint file as blacklist
            if phantom.is_fail(resp_status):
                return action_result.get_status()

        summary_data.update(hash_value_status)
        api_data["id"] = file_details.get("id", fingerprint_file_id)
        action_result.add_data({"hash_info": ar_hash_list, "fingerprint_file_info": api_data})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_system_info(self, param):
        """ This function is used to get system information.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        is_ip = False

        # Get mandatory parameter
        ip_hostname = param[consts.SEP_PARAM_IP_HOSTNAME]

        # To check if ip_hostname is IP or hostname
        if phantom.is_ip(ip_hostname):
            is_ip = True

        # Make rest call
        response_status, response_data = self._make_rest_call_abstract(consts.SEP_LIST_COMPUTER_ENDPOINTS,
                                                                       action_result)

        # Something went wrong
        if phantom.is_fail(response_status):
            return action_result.get_status()

        # Filter response
        for item in response_data['content']:
            if ((is_ip is False and ip_hostname.lower() in item['computerName'].lower()) or
                    (is_ip is True and ip_hostname in item['ipAddresses'])):
                item["ipAddresses"] = ", ".join(item["ipAddresses"])
                action_result.add_data(item)
                summary_data['system_found'] = True

        if action_result.get_data_size() == 0:
            return action_result.set_status(phantom.APP_ERROR, consts.SEP_INVALID_IP_HOSTNAME)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_endpoints(self, param):
        """ This function is used to list all endpoints configured on the device.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameter
        domain = param[consts.SEP_PARAM_DOMAIN]

        domain_id = self._get_domain_id_by_name(action_result, domain)

        if not domain_id:
            # set the action_result status to error
            return action_result.set_status(phantom.APP_ERROR, consts.SEP_INVALID_DOMAIN)

        params = {'domain': domain_id, 'pageIndex': 1}

        while True:
            response_status, response_data = self._make_rest_call_abstract(consts.SEP_LIST_COMPUTER_ENDPOINTS,
                                                                           action_result, params=params)

            if phantom.is_fail(response_status):
                return action_result.get_status()

            # Filter response
            for item in response_data['content']:
                if item["ipAddresses"]:
                    item["ipAddresses"] = ", ".join(item["ipAddresses"])
                action_result.add_data(item)
                summary_data['system_found'] = True

            if response_data['lastPage']:
                break

            params['pageIndex'] += 1

        summary_data['total_endpoints'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_command_status_by_id(self, action_result, command_id, timeout):
        """ Function to get command status.

        :action_result action_result: object of action result
        :command_id command_id: id of command
        :return status (Success / Failure), state_id_status
        """

        timeout = int(timeout)
        poll_seconds = 10
        state_ids = list()
        completion_state_ids = [3, 4, 5, 6]
        state_id = response_data = None

        while timeout > 0:
            if timeout > poll_seconds:
                timeout -= poll_seconds
            else:
                poll_seconds = timeout
                timeout = 0

            time.sleep(poll_seconds)
            params = {'pageIndex': 1}

            while True:
                state_ids = list()
                response_status, response_data = self._make_rest_call_abstract("{}/{}".format(
                    consts.SEP_GET_STATUS_ENDPOINT, command_id), action_result, params=params)

                if phantom.is_fail(response_status):
                    return action_result.get_status(), None

                for content in response_data['content']:
                    state_id = content["stateId"]
                    sub_state_id = content["subStateId"]
                    self.send_progress(
                        'Command State: {0}({1}), Sub-State: {2}({3})'.format(
                            state_id, COMMAND_STATE_DESC.get(str(state_id), "NA"), sub_state_id,
                            COMMAND_SUB_STATE_DESC.get(str(sub_state_id), 'NA')
                        )
                    )
                    state_ids.append(state_id)

                if response_data['lastPage']:
                    break

                params['pageIndex'] += 1

            # All computers have one of the completion state ids
            if set(state_ids) < (set(completion_state_ids)):
                timeout = 0

        for content in response_data['content']:
            if content['resultInXML']:
                content.update(xmltodict.parse(content['resultInXML']))
                content.pop("resultInXML")
            action_result.add_data(content)

        return action_result.set_status(phantom.APP_SUCCESS), COMMAND_STATE_DESC.get(str(state_id), "NA")

    def _scan_endpoint(self, param):
        """ Function to scan an endpoint.

        :param param: dictionary of input parameters
        :return status (Success / Failure)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting optional parameters
        computer_id = param.get(consts.SEP_PARAM_COMPUTER_ID)
        ip_hostname = param.get(consts.SEP_PARAM_IP_HOSTNAME)
        scan_type = param.get(consts.SEP_PARAM_SCAN_TYPE, 'QUICK_SCAN')

        search_key_field = list()

        # If none of the parameters are specified
        if not computer_id and not ip_hostname:
            self.debug_print(consts.SEP_PARAM_NOT_SPECIFIED.format(
                consts.SEP_PARAM_COMPUTER_ID, consts.SEP_PARAM_IP_HOSTNAME
            ))
            return action_result.set_status(phantom.APP_ERROR, consts.SEP_PARAM_NOT_SPECIFIED.format(
                consts.SEP_PARAM_COMPUTER_ID, consts.SEP_PARAM_IP_HOSTNAME
            ))

        # If computer_id is specified, then ip_hostname parameter will be ignored
        elif computer_id:
            search_key_field.append("uniqueId")
            value_to_search = [x.strip() for x in computer_id.split(',')]
        else:
            ip_hostname = [x.strip() for x in ip_hostname.split(',')]
            for index, item in enumerate(ip_hostname):
                # Checking if given value is an IP address
                if phantom.is_ip(item):
                    search_key_field.append("ipAddresses")
                elif phantom.is_hostname(item):
                    search_key_field.append("computerName")
                else:
                    return action_result.set_status(phantom.APP_ERROR, consts.SEP_IP_HOSTNAME_VALIDATION_ERROR)

            value_to_search = ip_hostname

        # Optional parameter
        timeout = param.get(consts.SEP_PARAM_TIMEOUT, 30)

        # Validate timeout
        if not str(timeout).isdigit():
            self.debug_print(consts.SEP_INVALID_TIMEOUT)
            return action_result.set_status(phantom.APP_ERROR, consts.SEP_INVALID_TIMEOUT), None

        # To check for given parameter computer id, IP/ Hostname
        get_endpoint_status, computer_id = self._get_endpoint_id_from_ip_hostname(action_result, value_to_search,
                                                                                  search_key_field)

        # Something went wrong while getting computer ID based on given IP or hostname
        if phantom.is_fail(get_endpoint_status):
            return action_result.get_status()

        # If no endpoint is found
        if not computer_id:
            self.debug_print(consts.SEP_DEVICE_NOT_FOUND.format(action="scan"))
            return action_result.set_status(phantom.APP_ERROR,
                                            consts.SEP_DEVICE_NOT_FOUND.format(action="scan"))

        computer_id = ",".join(list(set(computer_id)))

        scan_description = "Scan endpoint for computer ID(s) {computer_id}".format(computer_id=computer_id)
        curr_time = datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S %p")

        # Executing scan API on endpoint
        status, scan_resp = self._make_rest_call_abstract(
            consts.SEP_SCAN_ENDPOINT.format(computer_id=computer_id), action_result,
            headers={"Content-Type": "application/xml"},
            data=consts.SEP_SCAN_ENDPOINT_PAYLOAD.format(
                scan_type=scan_type, scan_description=scan_description, curr_time=curr_time
            ), method="post"
        )

        # Something went wrong while executing scan API on endpoint
        if phantom.is_fail(status):
            return action_result.get_status()

        try:
            summary_data["command_id"] = scan_resp.pop("commandID_computer")
        except:
            pass

        # Poll for command status
        command_status, state_id_status = self._get_command_status_by_id(action_result,
                                                                         summary_data.get("command_id"),
                                                                         timeout)
        # Something went wrong
        if phantom.is_fail(command_status):
            return action_result.get_status()

        summary_data["state_id_status"] = state_id_status

        return action_result.set_status(phantom.APP_SUCCESS)

    def _test_asset_connectivity(self, param):
        """ This function tests the connectivity of an asset with given credentials.

        :param param: (not used in this method)
        :return: status success/failure
        """

        action_result = ActionResult()

        self.save_progress(consts.SEP_CONNECTION_TEST_MSG)
        self.save_progress("Configured URL: {}".format(self._url))

        response_status = self._generate_api_token(action_result)

        # something went wrong
        if phantom.is_fail(response_status):
            # if phantom.is_fail(ret_value):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, consts.SEP_TEST_CONNECTIVITY_FAIL)
            return action_result.get_status()

        ret_val = self._validate_version(action_result)

        if phantom.is_fail(ret_val):
            self.set_status(ret_val, action_result.get_message())
            self.append_to_message(consts.SEP_TEST_CONNECTIVITY_FAIL)
            return self.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, consts.SEP_TEST_CONNECTIVITY_PASS)

        return action_result.get_status()

    def _validate_version(self, action_result):
        """ This function is used to validate version.

        :param action_result: object of action_result
        :return: status success/failure
        """

        ret_val, info = self._make_rest_call_abstract(consts.SEP_VERSION_ENDPOINT, action_result)
        if phantom.is_fail(ret_val):
            action_result.append_to_message(consts.SEP_VALIDATE_VERSION_FAILED)
            return action_result.get_status()
        device_version = info.get(consts.SEP_JSON_VERSION)
        if not device_version:
            return action_result.set_status(phantom.APP_ERROR, consts.SEP_UNABLE_TO_GET_VERSION)
        self.save_progress('Got device version: {0}'.format(device_version))
        version_regex = self.get_product_version_regex()
        if not version_regex:
            return phantom.APP_SUCCESS
        match = re.match(version_regex, device_version)
        if not match:
            message = "Version validation failed for App supported version '{0}'".format(version_regex)
            return action_result.set_status(phantom.APP_ERROR, message)
        self.save_progress(consts.SEP_VERSION_VALIDATED)
        return phantom.APP_SUCCESS

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_asset_connectivity': self._test_asset_connectivity,
            'list_domains': self._list_domains,
            'list_groups': self._list_groups,
            'get_status': self._get_status,
            'quarantine_device': self._quarantine_device,
            'unquarantine_device': self._unquarantine_device,
            'unblock_hash': self._unblock_hash,
            'block_hash': self._block_hash,
            'list_endpoints': self._list_endpoints,
            'get_system_info': self._get_system_info,
            'scan_endpoint': self._scan_endpoint
        }

        action = self.get_action_identifier()

        if action != phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            action_result = ActionResult(param)
            if phantom.is_fail(self._validate_version(action_result)):
                self.add_action_result(action_result)
                return action_result.get_status()

        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def finalize(self):

        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb

    pudb.set_trace()
    if len(sys.argv) < 2:
        print 'No test json specified as input'
        exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print json.dumps(in_json, indent=4)
        connector = Sep14Connector()
        connector.print_progress_message = True
        return_value = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(return_value), indent=4)
    exit(0)
