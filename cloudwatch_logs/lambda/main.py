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
# Forwards CloudWatch logs to Scalyr
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


class Cloudwatch2ScalyrException(Exception):
    def __init__(self, message, context=''):
        LOGGER.exception(f"Cloudwatch2Scalyr Exception: {message}")
        if DEBUG and context != '':
            print(f"Exception Context: \n\n{context}\n\n", file=sys.stderr)
        logging.shutdown()
        sys.exit(1)


def set_req_headers():
    return {
        'Content-Type': 'text/plain'
    }


def encode_url_params(params):
    try:
        encoded_params = urllib.parse.urlencode(params)
    except:
        raise Cloudwatch2ScalyrException('Couldn\'t encode url params', params)
    else:
        return encoded_params


def encode_post_data(data):
    try:
        encoded_data = data.encode('utf-8')
    except:
        raise Cloudwatch2ScalyrException('Couldn\'t encode post data', data)
    else:
        return encoded_data


def build_post_req(url, params, logEvents):
    url = url + '?' + encode_url_params(params)
    data = encode_post_data(logEvents)
    return urllib.request.Request(url, data=data, headers=set_req_headers())


def decode_response_body(r):
    try:
        decoded_body = json.loads(r.read().decode('utf-8'))
    except:
        raise Cloudwatch2ScalyrException('Couldn\'t decode response body', r.read())
    else:
        return decoded_body


def post(url, params, logEvents):
    req = build_post_req(url, params, logEvents)
    try:
        r = urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        raise Cloudwatch2ScalyrException(
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
    log_group_options = {}
    for pattern, options in LOG_GROUP_OPTIONS.items():
        if re.fullmatch(pattern, log_group):
            log_group_options = options
            LOGGER.info(f"{log_group} matches {pattern}")
    LOGGER.info('logGroupOptions: ' + json.dumps(log_group_options))
    return log_group_options


def build_params(message):
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
    LOGGER.info(f"Built url params: {json.dumps(params)}")
    params['token'] = WRITE_LOGS_KEY
    return params


def build_post_data(message):
    data = '\n'.join(list(map(lambda e: e['message'].rstrip(), message['logEvents'])))
    LOGGER.info(f"Post data: {data}")
    return data


def parse_message(message):
    params = build_params(message)
    logEvents = build_post_data(message)
    return [params, logEvents]


def decode_cw_data(cw_data):
    cw_zip_data = b64decode(cw_data)
    cw_raw_data = gzip.decompress(cw_zip_data)
    cw_json_data = json.loads(cw_raw_data)
    LOGGER.info(f"CloudWatch Message: {json.dumps(cw_json_data)}")
    return cw_json_data


def lambda_handler(event, context):
    if not WRITE_LOGS_KEY:
        raise Cloudwatch2ScalyrException('No Scalyr write logs key provided')
    cw_json_data = decode_cw_data(event['awslogs']['data'])
    params, logEvents = parse_message(cw_json_data)
    resp = post(UPLOAD_LOGS_URL, params, logEvents)
    LOGGER.info(f"Scalyr response: {json.dumps(resp)}")
