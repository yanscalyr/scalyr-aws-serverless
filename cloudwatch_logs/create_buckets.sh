#!/usr/bin/env bash

BUCKETS="scalyr-aws-serverless-us-west-1,scalyr-aws-serverless-us-west-2,scalyr-aws-serverless-ap-south-1,scalyr-aws-serverless-ap-northeast-2,scalyr-aws-serverless-ap-southeast-1,scalyr-aws-serverless-ap-northeast-1,scalyr-aws-serverless-ca-central-1,scalyr-aws-serverless-eu-central-1,scalyr-aws-serverless-eu-west-1,scalyr-aws-serverless-eu-west-2,scalyr-aws-serverless-eu-west-3,scalyr-aws-serverless-eu-north-1,scalyr-aws-serverless-sa-east-1"
#BUCKETS="scalyr-aws-serverless-us-east-2"

IFS=',' read -ra bucket_list <<< "$BUCKETS"

function determine_region_from_name() {
  result=${1#scalyr-aws-serverless-}
  echo "$result"
}

function create_policy() {
  bucket=$1
  cat <<EOT >> /tmp/policy-$bucket.txt
{
  "Statement": [ {
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$bucket/*"
  } ]
}
EOT
}

for i in "${bucket_list[@]}"; do
    bucket=$i
    region=`determine_region_from_name $i`
    create_policy $bucket
    echo "Creating $bucket"
    aws s3api create-bucket --bucket $bucket --region $region --create-bucket-configuration LocationConstraint=$region
    aws s3api put-bucket-policy --bucket $bucket --policy file:///tmp/policy-$bucket.txt
    echo "Done creating $bucket"
done


echo $bucket
