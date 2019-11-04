#!/bin/sh

aws ec2 describe-instances \
    | jq '[.Reservations[].Instances[] |
          {instance_id: .InstanceId,
           instance_type: .InstanceType,
           key: .KeyName,
	   name: (.Tags | map(select(.Key == "Name")))[0].Value,
           state: .State.Name}]'
