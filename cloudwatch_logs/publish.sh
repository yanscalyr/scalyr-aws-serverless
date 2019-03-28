#!/usr/bin/env bash
##
# Deployment instructions:
#   1.) Bump version in sam-template.yml Mappings->RegionMap for each region
#   2.) Bump version below in publish.sh
#   3.) Run publish.sh
#   4.) Update README.md with output templateURL from publish.sh
##

# The version number to publish, (must also be changed in sam-template.yml)
VERSION=1.0.2

# The S3 prefix to use, (must also be changed in sam-template.yml)
PREFIX=cloudwatch_logs

# Array of s3 buckets to publish to, (must also be changed in sam-template.yml)
BUCKETS[0]=scalyr-aws-serverless # (us-east-1)
BUCKETS[1]=scalyr-aws-serverless-us-east-2
BUCKETS[2]=scalyr-aws-serverless-us-west-1
BUCKETS[3]=scalyr-aws-serverless-us-west-2
BUCKETS[4]=scalyr-aws-serverless-ap-south-1
BUCKETS[5]=scalyr-aws-serverless-ap-northeast-2
BUCKETS[6]=scalyr-aws-serverless-ap-southeast-1
BUCKETS[7]=scalyr-aws-serverless-ap-northeast-1
BUCKETS[8]=scalyr-aws-serverless-ca-central-1
BUCKETS[9]=scalyr-aws-serverless-eu-central-1
BUCKETS[10]=scalyr-aws-serverless-eu-west-1
BUCKETS[11]=scalyr-aws-serverless-eu-west-2
BUCKETS[12]=scalyr-aws-serverless-eu-west-3
BUCKETS[13]=scalyr-aws-serverless-eu-north-1
BUCKETS[14]=scalyr-aws-serverless-sa-east-1

# Archive lambda code for publishing
APP_DIR="$( cd "$(dirname "$0")" ; pwd -P )"
cd $APP_DIR/lambda/cloudwatch_streamer && zip -qr Archive.zip .
cd $APP_DIR/lambda/cloudwatch_subscriber && zip -qr Archive.zip . && cd $APP_DIR

# Upload lambda deployment archives to each bucket
for BUCKET in "${BUCKETS[@]}"
do
    echo "Uploading packages to $BUCKET"
    aws s3 cp --quiet $APP_DIR/lambda/cloudwatch_streamer/Archive.zip \
        s3://$BUCKET/cloudwatch_logs/Streamer-$VERSION.zip
    aws s3 cp --quiet $APP_DIR/lambda/cloudwatch_subscriber/Archive.zip \
        s3://$BUCKET/cloudwatch_logs/Subscriber-$VERSION.zip
    aws s3 cp --quiet $APP_DIR/sam-template.yml \
        s3://$BUCKET/cloudwatch_logs/cloudwatch-logs-$VERSION.yml
done

# Remove deployment artifacts
rm $APP_DIR/lambda/cloudwatch_streamer/Archive.zip
rm $APP_DIR/lambda/cloudwatch_subscriber/Archive.zip

echo -e "\nupdate templateURL in README.md: https://s3.amazonaws.com/${BUCKETS[0]}/cloudwatch_logs/cloudwatch-logs-$VERSION.yml"
