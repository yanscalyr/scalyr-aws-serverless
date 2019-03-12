#!/usr/bin/env bash
BUCKET=scalyr-aws-serverless
PREFIX=cloudwatch_logs
VERSION=1.0.1

aws cloudformation package --template-file sam-template.yml \
    --output-template-file cloudwatch-logs-$VERSION.yml \
    --s3-bucket $BUCKET \
    --s3-prefix $PREFIX
aws s3 cp cloudwatch-logs-$VERSION.yml \
    s3://$BUCKET/$PREFIX/cloudwatch-logs-$VERSION.yml


echo -e "\n!!!! Don't forget to update the templateURL parameter of the LaunchStack button in README.md !!!!\n"
