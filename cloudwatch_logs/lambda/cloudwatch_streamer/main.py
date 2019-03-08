#!/usr/bin/env python3
#
# Copyright 2019 Scalyr Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------
#
# Forwards CloudWatch logs to Scalyr using the uploadLogs API documented
#  here: https://www.scalyr.com/help/api-uploadLogs
#
# author: Tom Gardiner <tom@teppen.io>
import os
import re
import sys
import json
import gzip
import boto3
import logging
import urllib.request
from uuid import uuid4
from base64 import b64decode

# Used as a way to identify the difference between warm and cold Lambda starts
# Lambda will re-use environments for some time, they will share the same ENVIRONMENT_ID
# Number of unique ENVIRONMENT_ID's == concurrent lambda invocations
ENVIRONMENT_ID = uuid4().hex

DEBUG = os.environ.get('DEBUG')
LOGGER = logging.getLogger()
if DEBUG == 'true':
    LOGGER.setLevel(logging.DEBUG)
else:
    LOGGER.setLevel(logging.ERROR)

WRITE_LOGS_KEY = os.environ.get('WRITE_LOGS_KEY')
if not WRITE_LOGS_KEY:
    WRITE_LOGS_KEY_ENCRYPTED = os.environ.get('WRITE_LOGS_KEY_ENCRYPTED')
    if WRITE_LOGS_KEY_ENCRYPTED:
        WRITE_LOGS_KEY = boto3.client('kms').decrypt(CiphertextBlob=b64decode(
            WRITE_LOGS_KEY_ENCRYPTED))['Plaintext'].decode('utf-8')

BASE_URL = os.environ.get('BASE_URL')
UPLOAD_LOGS_URL = BASE_URL + '/api/uploadLogs'

LOG_GROUP_OPTIONS = os.environ.get('LOG_GROUP_OPTIONS')
LOG_GROUP_OPTIONS = json.loads(LOG_GROUP_OPTIONS)


class CloudWatchStreamerException(Exception):
    """A custom exception class to print extra context before exiting"""

    def __init__(self, message, context=''):
        LOGGER.exception(f"CloudWatch Streamer Exception: {message}")
        if DEBUG and context != '':
            print(f"Exception Context: \n\n{context}\n\n", file=sys.stderr)
        logging.shutdown()
        sys.exit(1)


def build_req_headers():
    """Returns the request headers to be used for the Scalyr uploadLogs API request"""
    return {
        'Content-Type': 'text/plain'
    }


def encode_url_params(params):
    """Encodes a dict of k:v params as a URL-encoded string

    @param params: A dict of k:v parameters to be used in the request to the uploadLogs API
    @type params: dict

    @return: URL-encoded parameters to be used in the uploadLogs API request
    @rtype: str
    """
    try:
        encoded_params = urllib.parse.urlencode(params)
    except:
        raise CloudWatchStreamerException('Couldn\'t encode url params', params)
    else:
        return encoded_params


def encode_post_data(data):
    """Encodes a string of log-lines separated by '\n' into byte data

    @param data: A string containing each log-line from the CloudWatch Logs message separated
        by '\n' as required by the uploadLogs API
    @type param: str

    @return: A bytestring to be used as POST data in the uploadLogs API request
    @rtype: bytes
    """
    try:
        encoded_data = data.encode('utf-8')
    except:
        raise CloudWatchStreamerException('Couldn\'t encode post data', data)
    else:
        return encoded_data


def build_post_req(url, params, logEvents):
    """Builds a urllib request ready for submission to the Scalyr uploadLogs API

    Combines the uploadLogs API url, request parameters and a bytestring of
    log events into a urllib request

    @param url: The Scalyr uploadLogs API endpoint
    @param params: A dict of k:v parameters to be used in the request to the uploadLogs API
    @param logEvents: A string containing each log-line from the CloudWatch Logs message separated
        by '\n' as required by the uploadLogs API

    @type url: str
    @type param: dict
    @type: logEvents: str

    @return:  The urllib.request ready for submission to the Scalyr uploadLogs API
    @rtype: urllib.request
    """
    url = url + '?' + encode_url_params(params)
    data = encode_post_data(logEvents)
    return urllib.request.Request(url, data=data, headers=build_req_headers())


def decode_response_body(r):
    """Decodes and returns the Scalyr uploadLogs API response

    @param r: A urllib response object
    @type r: urllib.response

    @return: The uploadLogs API utf-8 decoded response body
    @rtype: dict
    """
    try:
        decoded_body = json.loads(r.read().decode('utf-8'))
    except:
        raise CloudWatchStreamerException('Couldn\'t decode response body', r.read())
    else:
        return decoded_body


def post(url, params, logEvents):
    """Performs an HTTP POST to the Scalyr uploadLogs API

    @param url: The Scalyr uploadLogs API endpoint
    @param params: A dict of k:v parameters to be used in the request to the uploadLogs API
    @param logEvents: A string containing each log-line from the CloudWatch Logs message separated
        by '\n' as required by the uploadLogs API

    @type url: str
    @type param: dict
    @type: logEvents: str

    @return: The HTTP status code and response body from Scalyr
    @rtype: dict
    """
    req = build_post_req(url, params, logEvents)
    try:
        r = urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        raise CloudWatchStreamerException(
            'Scalyr API returned HTTPError', json.dumps({
                'statusCode': e.code,
                'body': decode_response_body(e)
            }))
    else:
        return {
            'statusCode': r.code,
            'body': decode_response_body(r)
        }


def get_log_group_options(log_group):
    """Attempts to match the logGroup from the CloudWatch Logs message to the JSON object
    (LOG_GROUP_OPTIONS) provided in the Lambda environment using a regex full-match on the
    name of the logGroup

    @param log_group: The name of the logGroup from the CloudWatch Logs message
    @type log_group: str

    @return: An empty dict or a dict of options used to customise the request to the uploadLogs API
    @rtype: dict
    """
    log_group_options = {}
    for pattern, options in LOG_GROUP_OPTIONS.items():
        if re.fullmatch(pattern, log_group):
            log_group_options = options
            LOGGER.debug(f"{log_group} matches {pattern}")
    LOGGER.debug('logGroupOptions: ' + json.dumps(log_group_options))
    return log_group_options


def build_params(message):
    """Builds a dict of URL parameters extracted from the CloudWatch Logs message

    @param message: The CloudWatch Logs message and associated metadata
    @type message: dict

    @return: A dict of k:v parameters to be used in the request to the uploadLogs API
    @rtype: dict
    """
    options = get_log_group_options(message['logGroup'])
    params = {
        'token': 'REDACTED',
        'host': options.get(
            'serverHost', f"cloudwatch-{message['owner']}"),
        'logfile': options.get('logfile', message['logGroup']),
        'server-logStream': message['logStream'],
        'server-environmentId': ENVIRONMENT_ID,
        'parser': options.get('parser', 'cloudWatchLogs')
    }
    LOGGER.debug(f"Built url params: {json.dumps(params)}")
    params['token'] = WRITE_LOGS_KEY
    return params


def build_post_data(message):
    """Joins each log-line in the CloudWatch Logs message by '\n'

    @param message: The CloudWatch Logs message and associated metadata
    @type message: dict

    @return: A string containing each log-line from the CloudWatch Logs message separated
        by '\n' as required by the uploadLogs API
    @rtype: string
    """
    post_data = ''
    for logEvent in message['logEvents']:
        # Perform log manipulation here
        post_data += logEvent if logEvent.endswith('\n') else logEvent + '\n'
    LOGGER.debug(f"Post data: {post_data}")
    return post_data


def parse_message(message):
    """Parses a CloudWatch Logs message

    @param message: The CloudWatch Logs message and associated metadata
    @type message: dict

    @return: An array containing URL parameters and valid HTTP POST data ready for submission
        to the uploadLogs API
    @rtype: (dict, string)
    """
    params = build_params(message)
    logEvents = build_post_data(message)
    return params, logEvents


def decode_cw_data(cw_data):
    """Extracts and decodes CloudWatch Logs data
    CloudWatch data is base64 encoded and gzip compressed

    @param cw_data: The raw, gzipped CloudWatch Logs data
    @type cw_data: bytestring

    @return: The CloudWatch Logs message and associated metadata
    @rtype: dict
    """
    cw_zip_data = b64decode(cw_data)
    cw_raw_data = gzip.decompress(cw_zip_data)
    cw_json_data = json.loads(cw_raw_data)
    LOGGER.debug(f"CloudWatch Message: {json.dumps(cw_json_data)}")
    return cw_json_data


def lambda_handler(event, context):
    """Invoked by AWS to process the event and associated context
    https://docs.aws.amazon.com/lambda/latest/dg/python-programming-model-handler-types.html

    1.) Extracts and decodes the CloudWatch Logs data from the Lambda event
    2.) Parses the CloudWatch logs message into a urllib.request
    3.) Performs an HTTP POST to the Scalyr uploadLogs API

    @param event: The AWS event containing CloudWatch Logs data
    @param context: Provides runtime information regarding the Lambda event

    @type event: dict
    @type context: LambdaContext
    """
    if not WRITE_LOGS_KEY:
        raise CloudWatchStreamerException('No Scalyr write logs key provided')
    cw_json_data = decode_cw_data(event['awslogs']['data'])
    params, logEvents = parse_message(cw_json_data)
    resp = post(UPLOAD_LOGS_URL, params, logEvents)
    LOGGER.debug(f"Scalyr response: {json.dumps(resp)}")
