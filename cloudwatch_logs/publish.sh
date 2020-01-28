#!/usr/bin/env bash
#
# Helper script for publishing CloudFormation script to all S3 buckets where
# running the Lambda is supported.

APP_DIR="$( cd "$(dirname "$0")" ; pwd -P )"

# A comma separated list of the buckets where to publish the CF script.
BUCKETS="scalyr-aws-serverless,scalyr-aws-serverless-us-east-2,scalyr-aws-serverless-us-west-1,scalyr-aws-serverless-us-west-2,scalyr-aws-serverless-ap-south-1,scalyr-aws-serverless-ap-northeast-2,scalyr-aws-serverless-ap-southeast-1,scalyr-aws-serverless-ap-northeast-1,scalyr-aws-serverless-ca-central-1,scalyr-aws-serverless-eu-central-1,scalyr-aws-serverless-eu-west-1,scalyr-aws-serverless-eu-west-2,scalyr-aws-serverless-eu-west-3,scalyr-aws-serverless-eu-north-1,scalyr-aws-serverless-sa-east-1,scalyr-aws-serverless-ap-southeast-2"
# The prefix for uploading the objects to S3.
PREFIX=cloudwatch_logs
# The version number of the CL script.
VERSION=`cat $APP_DIR/VERSION`

TMP_DIR=`mktemp -d`;
trap "rm -rf $TMP_DIR" EXIT;


function print_usage() {
cat <<EOF
Usage $0 [options] where options are:
    -h,--help            Display this help message."
    --buckets <BUCKET>
    --prefix <PREFIX>
    --version <VERSION>
EOF
}

function die() {
  echo "$1";
  exit 1;
}

# Only write $1 to STDOUT if $2 is non-zero
function report_progress() {
  if [ -z "$2" ]; then
    echo $1
  fi
}

# Given a bucket name, look up with region it exists in using AWS S3 api.
function determine_bucket_region() {
  get_bucket_output=`aws s3api get-bucket-location --bucket $1 2>&1` || return;
  if echo "$get_bucket_output" | grep Constraint | grep null > /dev/null; then
    echo "us-east-1"
  else
    echo $get_bucket_output | grep Constraint | cut -d\" -f4
  fi
}

# Write out the header for the mapping portion of the SAM template.
function emit_mapping_header() {
  cat <<EOF
Mappings:
  RegionMap:
EOF
}

# Write out the mapping entry for the specified bucket ($1) in the given
# region ($2).
function emit_mapping_entry() {
  cat <<EOF
    $2:
      bucket: '$1'
      prefix: '$PREFIX'
      version: $VERSION
EOF
}

# Whether or not to write the normal/non-error messages to stdout
QUIET=""

# Handle the commandline options
while (( $# > 0)); do
  case "$1" in

    -h|--help)
      print_usage;
      exit 0;;

    --buckets)
      BUCKETS="$2"
      shift;
      shift;;

    --prefix)
      PREFIX="$2"
      shift;
      shift;;

    --version)
      VERSION="$2"
      shift;
      shift;;

    --quiet)
      QUIET="yes";
      shift;;

    *)
      echo "Unrecognized option: $1";
      exit 1;
      break;;
  esac
done

report_progress "Gathering bucket information" $QUIET

IFS=',' read -ra bucket_list <<< "$BUCKETS"
bucket_regions=()

# Because querying the region for N buckets takes a while, we will do them
# all in parallel, with each subprocess writing its result to an entry in
# TMP_DIR.
# First, start all of the jobs, getting the pids in a list.
bucket_lookup_pids=()
for i in "${bucket_list[@]}"; do
  determine_bucket_region $i > $TMP_DIR/$i &
  bucket_lookup_pids+=("$!")
done

# Go back and wait until all of those pids are done and ensure they were
# successful.
for i in "${!bucket_list[@]}"; do
  wait "${bucket_lookup_pids[$i]}" || die "Failed looking up bucket ${bucket_list[$i]}";
  bucket_regions+=(`cat $TMP_DIR/"${bucket_list[$i]}"`)
done

# Create the SAM template file by replacing the existing bucket list (in the
# mapping section) with the buckets we want to use here including the version
# number.
report_progress "Preparing template file" $QUIET

emit_mapping_header > $TMP_DIR/middle.yml
for i in "${!bucket_list[@]}"; do
  emit_mapping_entry ${bucket_list[$i]} ${bucket_regions[$i]} >> $TMP_DIR/middle.yml
done

# Grab the sections of the SAM template before and after the mapping section
# using some hard-coded comments.
sed -n '1,/BEGIN MAPPINGS/ p' $APP_DIR/sam-template.yml > $TMP_DIR/start.yml
sed -n '/END MAPPINGS/,$ p' $APP_DIR/sam-template.yml > $TMP_DIR/end.yml

cat $TMP_DIR/start.yml $TMP_DIR/middle.yml $TMP_DIR/end.yml > $TMP_DIR/cloudwatch-logs-$VERSION.yml

report_progress "Creating Lambda packages" $QUIET

cd $APP_DIR/lambda/cloudwatch_streamer && zip -qr $TMP_DIR/Streamer-$VERSION.zip . || die "Failed to create the Lambda for the streamer"
cd $APP_DIR/lambda/cloudwatch_subscriber && zip -qr $TMP_DIR/Subscriber-$VERSION.zip . || die "Failed to create the Lambda for the subscriber"

cd $APP_DIR

report_progress "Uploading packages to S3 buckets" $QUIET
for i in "${bucket_list[@]}"
do
    echo "  ... $i"
    aws s3 cp --quiet $TMP_DIR/Streamer-$VERSION.zip \
        s3://$i/cloudwatch_logs/Streamer-$VERSION.zip \
          || die "Failed uploading streamer to $i"
    aws s3 cp --quiet $TMP_DIR/Subscriber-$VERSION.zip \
        s3://$i/cloudwatch_logs/Subscriber-$VERSION.zip \
          || die "Failed uploading subscriber to $i"
    aws s3 cp --quiet $TMP_DIR/cloudwatch-logs-$VERSION.yml \
        s3://$i/cloudwatch_logs/cloudwatch-logs-$VERSION.yml \
          || die "Failed CloudFormation template $i"
done

report_progress "Success" $QUIET
report_progress "Be sure to change the templateURL to https://${bucket_list[0]}.s3.amazonaws.com/$PREFIX/cloudwatch-logs-$VERSION.yml" $QUIET
