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
# CloudFormation custom resource to subscribe loggroups to the
# cloudWatch2scaylr2 lambda
#
# author: Tom Gardiner <tom@teppen.io>
import re
import json
import boto3
import signal
import logging
from botocore.vendored import requests

CWLOGS = boto3.client('logs')

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


def set_resp_headers(json_resp_body):
    return {
        'content-type': '',
        'content-length': str(len(json_resp_body))
    }


def build_resp(event, context, resp_status):
    resp_body = {
        'Status': resp_status,
        'Reason': f"See CloudWatch Log Stream: {context.log_stream_name}",
        'PhysicalResourceId': event.get('PhysicalResourceId', context.invoked_function_arn),
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId']
    }
    return json.dumps(resp_body)


def send_resp(event, context, resp_status):
    resp_url = event['ResponseURL']
    json_resp_body = build_resp(event, context, resp_status)
    LOGGER.info(f"Built response data: {json_resp_body}")
    try:
        resp = requests.put(resp_url, data=json_resp_body, headers=set_resp_headers(json_resp_body))
        LOGGER.info(f"Status code: {resp.reason}")
    except Exception as e:
        LOGGER.exception(f"Failed sending response: {e}")
        raise


def load_log_group_options(event, resource_properties):
    try:
        log_group_options = json.loads(event[resource_properties]['LogGroupOptions'])
    except:
        LOGGER.exception(f"Error loading {resource_properties} LogGroupOptions")
        raise
    else:
        LOGGER.info(f"Loaded {resource_properties} LogGroupOptions: " + json.dumps(log_group_options))
        return log_group_options


def get_log_groups():
    log_groups = []
    kwargs = {}
    try:
        while True:
            resp = CWLOGS.describe_log_groups(**kwargs)
            for log_group in resp['logGroups']:
                log_groups.append(log_group['logGroupName'])
            try:
                kwargs['nextToken'] = resp['nextToken']
            except KeyError:
                break
    except:
        LOGGER.exception('Error fetching log groups from AWS')
        raise
    else:
        LOGGER.info('Loaded log groups from AWS: ' + json.dumps(log_groups))
        return log_groups


def match_log_groups(aws_log_groups, log_group_options):
    matching_log_groups = {}
    for pattern, options in log_group_options.items():
        for aws_log_group in aws_log_groups:
            if re.fullmatch(pattern, aws_log_group):
                matching_log_groups[aws_log_group] = options
    LOGGER.info('Matched log groups: ' + json.dumps(matching_log_groups))
    return matching_log_groups


def diff_log_groups(log_group_options, old_log_group_options):
    log_group_names = set(log_group_options)
    old_log_group_names = set(old_log_group_options)
    added = log_group_names.difference(old_log_group_names)
    deleted = old_log_group_names.difference(log_group_names)
    intersecting = log_group_names.intersection(old_log_group_names)
    updated = []
    for log_group in intersecting:
        if not log_group_options[log_group] == old_log_group_options[log_group]:
            updated.append(log_group)
    return added, set(updated), deleted


def put_subscription_filter(log_group_name, options, destination_arn):
    try:
        CWLOGS.put_subscription_filter(
            filterPattern=options.get('filterPattern', ''),
            filterName=options.get('filterName', 'cloudwatch2scalyr'),
            logGroupName=log_group_name,
            destinationArn=destination_arn
        )
    except:
        LOGGER.exception(f"Error subscribing logGroup: {log_group_name}")
        raise
    else:
        LOGGER.info(f"Subscribed logGroup: {log_group_name}")


def delete_subscription_filter(log_group_name, options, destination_arn):
    try:
        CWLOGS.delete_subscription_filter(
            filterName=options.get('filterName', 'cloudwatch2scalyr'),
            logGroupName=log_group_name
        )
    except CWLOGS.exceptions.ResourceNotFoundException as e:
        LOGGER.error(f"Error unsubscribing logGroup: {log_group_name}: {e}")
    except:
        LOGGER.exception(f"Error unsubscribing logGroup: {log_group_name}")
        raise
    else:
        LOGGER.info(f"Unsubscribed logGroup: {log_group_name}")


def process_cf_event(event):
    auto_subscribe_log_groups = event['ResourceProperties']['AutoSubscribeLogGroups']
    destination_arn = event['ResourceProperties']['DestinationArn']

    if auto_subscribe_log_groups == 'true':
        aws_log_groups = get_log_groups()
        log_group_options = load_log_group_options(event, 'ResourceProperties')
        matched_log_group_options = match_log_groups(aws_log_groups, log_group_options)

        if event['RequestType'] == 'Create':
            for log_group_name, options in matched_log_group_options.items():
                put_subscription_filter(log_group_name, options, destination_arn)
        elif event['RequestType'] == 'Update':
            old_log_group_options = load_log_group_options(event, 'OldResourceProperties')
            old_matched_log_group_options = match_log_groups(aws_log_groups, old_log_group_options)
            added, updated, deleted = diff_log_groups(matched_log_group_options, old_matched_log_group_options)
            for log_group_name, options in matched_log_group_options.items():
                if log_group_name in added or log_group_name in updated:
                    put_subscription_filter(log_group_name, options, destination_arn)
            for log_group_name, options in old_matched_log_group_options.items():
                if log_group_name in deleted:
                    delete_subscription_filter(log_group_name, options, destination_arn)
        elif event['RequestType'] == 'Delete':
            for log_group_name, options in matched_log_group_options.items():
                delete_subscription_filter(log_group_name, options, destination_arn)


def lambda_handler(event, context):
    def timeout_handler(sig_num, frame):
        LOGGER.exception('Lambda timed out before completion')
        send_resp(event, context, "FAILED")
    signal.signal(signal.SIGALRM, timeout_handler)

    LOGGER.info('Recieved CF event: ' + json.dumps(event))
    signal.alarm(int(context.get_remaining_time_in_millis() / 1000) - 1)

    # Ensure a repsonse is always sent to CF to avoid stuck CF Stacks
    try:
        process_cf_event(event)
    except:
        send_resp(event, context, "FAILED")
    else:
        send_resp(event, context, "SUCCESS")
        signal.alarm(0)
