# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from securitytrails import *

# Usage of the consts file is recommended
# from securitytrails_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SecuritytrailsConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SecuritytrailsConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            # auth=(username, password),  # basic authentication
                            data=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in own self variable.
        api_key = config.get('api_key')

        # Create a new Security Trails Python Object
        s = SecurityTrails(api_key=api_key)

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # Connect to Phantom Endpoint
        self.save_progress("Connecting to endpoint")

        if s.test_connect() is False:
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()
        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_domain(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in own self variable.
        api_key = config.get('api_key')

        # Create a new Security Trails Python Object
        s = SecurityTrails(api_key=api_key)

        # Pass domain to the search
        domain = param['domain']

        # Issue request to get_domain
        result = s.get_domain(domain)

        if (result is False):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Convert output to json
        response = json.loads(result)

        # Create new python dictionary to store output
        data_output = {}

        # Create IPV4 Array
        ipv4_array = []

        # Add 'A' record fields to new json dictionary
        for ip in response['current_dns']['a']['values']:
            ipv4_array.append({"type": "a", "ip": ip['ip']})

        # Add A Records to Output
        data_output['a'] = ipv4_array

        # Create IPV4 Array
        ipv6_array = []

        # Add 'AAAA' record fields to existing json dictionary
        for ip in response['current_dns']['aaaa']['values']:
            ipv6_array.append({"type": "aaaa", "ipv6": ip['ipv6']})

        # Add AAAA Records to Output
        data_output['aaaa'] = ipv6_array

        # Add Alexa Rank to data_output
        data_output['alexa_rank'] = response['alexa_rank']

        # Add hostname to output
        data_output['hostname'] = response['hostname']

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['domain'] = domain

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_whois_domain(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in own self variable.
        api_key = config.get('api_key')

        # Create a new Security Trails Python Object
        s = SecurityTrails(api_key=api_key)

        # Pass domain to the search
        domain = param['domain']

        # Issue request to get_whois
        result = s.get_whois(domain)

        # If the result fails
        if (result is False):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Convert output to json
        response = json.loads(result)

        # Create new python dictionary to store output
        data_output = response

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['domain'] = domain

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_whois_history(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in own self variable.
        api_key = config.get('api_key')

        # Create a new Security Trails Python Object
        s = SecurityTrails(api_key=api_key)

        # Pass domain to the search
        domain = param['domain']

        # Issue request to get_whois
        result = s.get_history_whois(domain)

        # If the result fails
        if (result is False):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Convert output to json
        response = json.loads(result)

        # Create new python dictionary to store output
        data_output = response

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['domain'] = data_output['domain']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_searcher(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in own self variable.
        api_key = config.get('api_key')

        # Create a new Security Trails Python Object
        s = SecurityTrails(api_key=api_key)

        # Pass domain to the search
        search_filter = param['filter']

        # Pass domain to the search
        search_filter_string = param['filter']

        # Pass domain to the search
        keyword = param['keyword']

        if keyword:
            params = {search_filter: search_filter_string, "keyword": keyword }

        else:
            # Create parameter variable to pass as kwargs to the result variable
            params = {search_filter: search_filter_string}

        # Issue request to get_whois
        result = s.domain_searcher(**params)

        # If the result fails
        if (result is False):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Convert output to json
        response = json.loads(result)

        # Create new python dictionary to store output
        data_output = response

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['domain'] = params

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_category(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in own self variable.
        api_key = config.get('api_key')

        # Create a new Security Trails Python Object
        s = SecurityTrails(api_key=api_key)

        # Pass domain to the search
        domain = param['domain']

        # Issue request to get_whois
        result = s.get_tags(domain)

        # If the result fails
        if (result is False):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Convert output to json
        response = json.loads(result)

        # If domain has no tags
        if len(response['tags'] == 0):
            response['tags'] = "None"

        # Create new python dictionary to store output
        data_output = response

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['domain'] = data_output['domain']
        summary['tags'] = data_output['tags']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_subdomain(self, param):

                # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in own self variable.
        api_key = config.get('api_key')

        # Create a new Security Trails Python Object
        s = SecurityTrails(api_key=api_key)

        # Pass domain to the search
        domain = param['domain']

        # Issue request to get_subdomain
        result = s.get_subdomain(domain)

        # If the result fails
        if (result is False):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Convert output to json
        response = json.loads(result)

        # Create an empty array for pushing subdomains into
        outputArray = []

        # For each subdomain that is listed
        for a in response['subdomains']:
            outputArray.append({"domain": a + "." + domain})

        # Create new python dictionary to store output
        data_output = outputArray

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['domain'] = domain

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_history(self, param):

                # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in own self variable.
        api_key = config.get('api_key')

        # Create a new Security Trails Python Object
        s = SecurityTrails(api_key=api_key)

        # Pass domain to the search
        domain = param['domain']

        # Pass domain to the search
        record_type = param['record_type']

        # Issue request to get_whois
        result = s.get_history_dns(domain, record_type)

        # If the result fails
        if (result is False):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Convert output to json
        response = json.loads(result)

        # Format output
        outputArray = []
        for a in response['records']:
            for value in a['values']:
                option = {}
                if len(a['organizations']) == 1:
                    option['organizations'] = a['organizations'][0]
                else:
                    option['organizations'] = a['organizations']
                option['first_seen'] = a['first_seen']
                option['last_seen'] = a['last_seen']
                option['ip'] = value['ip']
                outputArray.append(option)

        # Convert the output into a dictionary
        results = {"results": outputArray, "domain": domain}

        # Convert the results variable into json
        resultsJson = json.loads(json.dumps(results))

        # Create new python dictionary to store output
        data_output = resultsJson

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['domain'] = data_output['domain']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'lookup_domain':
            ret_val = self._handle_lookup_domain(param)

        elif action_id == 'whois_domain':
            ret_val = self._handle_whois_domain(param)

        elif action_id == 'whois_history':
            ret_val = self._handle_whois_history(param)

        elif action_id == 'domain_searcher':
            ret_val = self._handle_domain_searcher(param)

        elif action_id == 'domain_category':
            ret_val = self._handle_domain_category(param)

        elif action_id == 'domain_subdomain':
            ret_val = self._handle_domain_subdomain(param)

        elif action_id == 'domain_history':
            ret_val = self._handle_domain_history(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SecuritytrailsConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
