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
import random
import hashlib
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

BASE_URL = os.environ.get('BASE_URL', '')
UPLOAD_LOGS_URL = BASE_URL + '/api/uploadLogs'

LOG_GROUP_OPTIONS = os.environ.get('LOG_GROUP_OPTIONS', '{}')
LOG_GROUP_OPTIONS = json.loads(LOG_GROUP_OPTIONS)

class CloudWatchStreamerException(Exception):
    """A custom exception class to print extra context before exiting"""

    def __init__(self, message, context='', level=logging.ERROR, exc_info=True):
        id = ENVIRONMENT_ID
        LOGGER.log(level, f"CloudWatch Streamer Exception{id}: {message}", exc_info=exc_info)
        if DEBUG and context != '':
            print(f"Exception Context: \n\n{context}\n\n", file=sys.stderr)


class LogLineSampler(object):
    """Encapsulates all of the configured sampling rules to perform on lines from a single log file.

    It contains a list of filters, specified as regular expressions and a corresponding pass rate
    (a number between 0 and 1 inclusive) for each filter.  When a line is processed, each filter
    regular expression is matched against the line in order.  If a expression matches any portion of the
    line, then its pass rate is used to determine if that line should be included in the output.  A random number
    is generated and if it is greater than the filter's pass rate, then the line is included.  The first filter that
    matches a line is used.

    Copied and modified from https://github.com/scalyr/scalyr-agent-2/blob/master/scalyr_agent/log_processing.py
    Any non-trivial changes to the above should be reflected here.
    TODO: Have a common library for this code
    """

    def __init__(self):
        """Initializes an instance.
        """
        self.__sampling_rules = []
        self.total_passes = 0

    def process_line(self, input_line):
        """Performs all configured sampling operations on the input line and returns whether or not it should
        be kept.  If it should be kept, then a float is returned indicating the sampling rate of the rule that
        allowed it to be included.  Otherwise, None.

        See the class description for the algorithm that determines which lines are returned.

        @param input_line: The input line.

        @return: A float between 0 and 1 if the input line should be kept, the sampling rate of the rule that allowed
            it to be included.  Otherwise, None.
        """

        if len(self.__sampling_rules) == 0:
            self.total_passes += 1
            return 1.0

        sampling_rule = self.__find_first_match(input_line)
        if sampling_rule is None:
            return 1.0
        else:
            sampling_rule.total_matches += 1
            if self.__flip_biased_coin(sampling_rule.sampling_rate):
                sampling_rule.total_passes += 1
                self.total_passes += 1
                return sampling_rule.sampling_rate
        return None

    def add_rule(self, match_expression, sample_rate):
        """Appends a new sampling rule.  Any line that contains a match for match expression will be sampled with
        the specified rate.

        @param match_expression: The regular expression that much match any part of a line to activie the rule.
        @param sample_rate: The sampling rate, expressed as a number between 0 and 1 inclusive.
        """
        self.__sampling_rules.append(SamplingRule(match_expression, sample_rate))

    def __find_first_match(self, line):
        """Returns the first sampling rule to match the line, if any.

        @param line: The input line to match against.

        @return: The first sampling rule to match any portion of line.  If none
            match, then returns None.
        """
        for sampling_rule in self.__sampling_rules:
            if sampling_rule.match_expression.search(line) is not None:
                return sampling_rule
        return None

    def __flip_biased_coin(self, bias):
        """Flip a biased coin and return True if it comes up head.

        @param bias: The probability the coin will come up heads.
        @type bias: float
        @return:  True if it comes up heads.
        @rtype: bool
        """
        if bias == 0:
            return False
        elif bias == 1:
            return True
        else:
            return self._get_next_random() < bias

    def _get_next_random(self):
        """Returns a random between 0 and 1 inclusive.

        This is used for testing.
        """
        return random.random()


class SamplingRule(object):
    """Encapsulates all data for one sampling rule."""

    def __init__(self, match_expression, sampling_rate):
        self.match_expression = re.compile(match_expression, flags=re.UNICODE)
        self.sampling_rate = sampling_rate
        self.total_matches = 0
        self.total_passes = 0


class LogLineRedacter(object):
    """Encapsulates all of the configured redaction rules to perform on lines from a single log file.

    It contains a list of redaction filters, specified as regular expressions, that are applied against
    all lines being processed, in order.  If a redaction filter's regular expression matches any portion
    of the line, the matched text is replaced with the text specified by the redaction rule, which may
    include portions of the matched text using the $1, etc operators from the regular expression.

    Redaction rules can match each line multiple times.

    Copied and modified from https://github.com/scalyr/scalyr-agent-2/blob/master/scalyr_agent/log_processing.py
    Any non-trivial changes to the above should be reflected here.
    TODO: Have a common library for this code
    """

    # Indicator in the replacement text[optional] to hash the group content.
    # eg replacement string of foo\\1=\\H2 will replace the second group with its hashed content
    HASH_GROUP_INDICATOR = "H"

    def __init__(self):
        """Initializes an instance.
        """

        self.__redaction_rules = []
        self.total_redactions = 0

    def process_line(self, input_line):
        """Performs all configured redaction rules on the input line and returns the results.

        See the class description for the algorithm that determines how the rules are applied.

        @param input_line: The input line.

        @return: A sequence of two elements, the line with the redaction applied (if any) and True or False
            indicating if a redaction was applied.
        """

        if len(self.__redaction_rules) == 0:
            return input_line, False

        modified_it = False

        for redaction_rule in self.__redaction_rules:
            (input_line, redaction) = self.__apply_redaction_rule(input_line, redaction_rule)
            modified_it = modified_it or redaction

        return input_line, modified_it

    def add_redaction_rule(self, redaction_expression, replacement_text, hash_salt=''):
        """Appends a new redaction rule to this instance.

        @param redaction_expression: The regular expression that must match some portion of the line.
        @param replacement_text: The text to replace the matched text with. May include \1 etc to use a portion of the
            matched text.
        @param hash_salt: [optional] If hashing is set, then the cryptographic salt to be used

        @type hash_salt: str
        """

        self.__redaction_rules.append(
            RedactionRule(
                redaction_expression, replacement_text, hash_salt=hash_salt
            )
        )

    def __apply_redaction_rule(self, line, redaction_rule):
        """Applies the specified redaction rule on line and returns the result.

        @param line: The input line
        @param redaction_rule: The redaction rule.

        @return: A sequence of two elements, the line with the redaction applied (if any) and True or False
            indicating if a redaction was applied.
        """

        def __replace_groups_with_hashed_content(re_ex, replacement_ex, line):

            _matches = re.finditer(re_ex, line)

            if not _matches:
                # if no matches, return the `line` as such
                return line, None

            replacement_matches = 0

            # last_match_index captures the index of the last match position
            # that will help us rebuild the original string with replaced pattern
            last_match_index = 0
            replaced_string = ""

            for _match in _matches:
                _groups = _match.groups()
                # `replaced_group` will initially hold the replacement expression `replacement_ex`
                # and the group expressions like \\1 or \\H2 etc. will be substituted with the actual
                # group value or the hashed group value depending on whether the group needs hashing or not
                # Once substituted, this can be used to replace the matched string portion
                replaced_group = replacement_ex
                for _group_index, _group in enumerate(_groups):
                    # for each group in a match, replace the `replacement_ex` with either its `group` content, or
                    # the hash of the `group` depending on the hash indicator \\1 vs \\H1 etc.
                    group_hash_indicator = "\\%s%d" % (LogLineRedacter.HASH_GROUP_INDICATOR, _group_index + 1)
                    replacement_matches += 1
                    if group_hash_indicator in replacement_ex:
                        # the group needs to be hashed
                        replaced_group = replaced_group.replace(
                            group_hash_indicator,
                            hashlib.md5((_group + redaction_rule.hash_salt).encode()).hexdigest(),
                            1
                        )
                    else:
                        # the group does not need to be hashed
                        replaced_group = replaced_group.replace("\\%d" % (_group_index + 1), _group, 1)
                # once we have formed the replacement expression, we just need to replace the matched
                # portion of the `line` with the `replaced_group` that we just built
                replaced_string += line[last_match_index: _match.start()]
                replaced_string += replaced_group
                # forward the last match index to the end of the match group
                last_match_index = _match.end()

            replaced_string += line[last_match_index:]
            return replaced_string, replacement_matches

        try:
            if redaction_rule.hash_redacted_data:
                # out of these matched groups,
                (result, matches) = __replace_groups_with_hashed_content(
                    redaction_rule.redaction_expression,
                    redaction_rule.replacement_text,
                    line
                )
            else:
                (result, matches) = re.subn(
                    redaction_rule.redaction_expression, redaction_rule.replacement_text, line
                )
        except UnicodeDecodeError:
            # if our line contained non-ascii characters and our redaction_rules
            # are unicode, then the previous replace will fail.
            # Try again, but this time convert the line to utf-8, replacing any
            # invalid characters with the unicode replacement character
            if redaction_rule.hash_redacted_data:
                (result, matches) = __replace_groups_with_hashed_content(
                    redaction_rule.redaction_expression,
                    redaction_rule.replacement_text,
                    line.decode('utf-8', 'replace')
                )
            else:
                (result, matches) = re.subn(
                    redaction_rule.redaction_expression,
                    redaction_rule.replacement_text,
                    line.decode('utf-8', 'replace')
                )

        if matches > 0:
            self.total_redactions += 1
            redaction_rule.total_lines += 1
            redaction_rule.total_redactions += matches
        return result, matches > 0


class RedactionRule(object):
    """Encapsulates all data for one redaction rule."""

    def __init__(self, redaction_expression, replacement_text, hash_salt=''):
        self.redaction_expression = re.compile(redaction_expression, flags=re.UNICODE)
        self.replacement_text = replacement_text
        self.hash_salt = hash_salt
        self.total_lines = 0
        self.total_redactions = 0

    @property
    def hash_redacted_data(self):
        return ("\\%s" % (LogLineRedacter.HASH_GROUP_INDICATOR)) in self.replacement_text


def build_req_headers():
    """Returns the request headers to be used for the Scalyr uploadLogs API request"""
    if DEBUG == 'true':
        id = ENVIRONMENT_ID
        return {
            'Content-Type': 'text/plain',
            'User-Agent': f"cloudwatch-log-debug-streamer-{id}"
        }
    else:
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
    @rtype: dict if Scalyr returns JSON, str if not
    """
    raw_body = r.read()
    try:
        decoded_body = json.loads(raw_body.decode('utf-8'))
    except json.decoder.JSONDecodeError:
        # Scalyr has returned a non-json response, usually a temporary issue
        # Lambda will automatically retry the invocation twice, with delays between retries
        raise CloudWatchStreamerException(
            'Problem communicating with Scalyr uploadLogs API. Request will be retried twice',
            raw_body,
            level=logging.INFO,
            exc_info=False
        )
    except:
        raise CloudWatchStreamerException('Couldn\'t decode response body', raw_body)
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
    """Samples, redacts, and joins each log-line in the CloudWatch Logs message by '\n'

    @param message: The CloudWatch Logs message and associated metadata
    @type message: dict

    @return: A string containing each log-line to be set to Scalyr from the CloudWatch Logs message separated
        by '\n' as required by the uploadLogs API
    @rtype: str
    """
    post_data = ''
    options = get_log_group_options(message['logGroup'])
    sampler = LogLineSampler()
    redactor = LogLineRedacter()
    for rule in options.get('sampling_rules', {}):
        sampler.add_rule(rule['match_expression'], float(rule['sampling_rate']))
    for rule in options.get('redaction_rules', {}):
        redactor.add_redaction_rule(rule['match_expression'], rule.get('replacement', ''), rule.get('hash_salt', ''))
    for logEvent in message['logEvents']:
        # Perform log manipulation here
        if not sampler.process_line(logEvent['message']):
            continue
        (log_line, redacted) = redactor.process_line(logEvent['message'])
        if log_line.endswith('\n'):
            post_data += log_line
        else:
            post_data += log_line + '\n'
    LOGGER.debug(f"Post data: {post_data}")
    return post_data


def parse_message(message):
    """Parses a CloudWatch Logs message

    @param message: The CloudWatch Logs message and associated metadata
    @type message: dict

    @return: An array containing URL parameters and valid HTTP POST data ready for submission
        to the uploadLogs API
    @rtype: (dict, str)
    """
    params = build_params(message)
    logEvents = build_post_data(message)
    return params, logEvents


def decode_cw_data(cw_data):
    """Extracts and decodes CloudWatch Logs data
    CloudWatch data is base64 encoded and gzip compressed

    @param cw_data: The raw, gzipped CloudWatch Logs data
    @type cw_data: bytes

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
