#!/bin/bash
# Assume the sim-attacker role ONCE, then run all given commands in that one session.
# Usage: ./as-attacker.sh   (then it runs a fixed recon sequence)
ARN=$(aws iam get-role --role-name backup-operator --query Role.Arn --output text)
CREDS=$(aws sts assume-role --role-arn "$ARN" --role-session-name session --query Credentials --output json)
export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | python3 -c "import json,sys;print(json.load(sys.stdin)['AccessKeyId'])")
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | python3 -c "import json,sys;print(json.load(sys.stdin)['SecretAccessKey'])")
export AWS_SESSION_TOKEN=$(echo "$CREDS" | python3 -c "import json,sys;print(json.load(sys.stdin)['SessionToken'])")
echo "attacker session key: $AWS_ACCESS_KEY_ID"
echo "-- recon as attacker --"
aws iam list-users --query 'Users[].UserName' --output text
aws s3 ls
aws ec2 describe-instances --region us-east-2 --query 'Reservations[].Instances[].InstanceId' --output text
aws iam list-roles --query 'Roles[].RoleName' --output text | head
aws guardduty list-detectors --output text
