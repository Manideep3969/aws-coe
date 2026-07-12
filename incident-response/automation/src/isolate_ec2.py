import json
import boto3
import os

ec2 = boto3.client('ec2')
sns = boto3.client('sns')
ssm = boto3.client('ssm')

ISOLATION_SG_ID = os.environ['ISOLATION_SG_ID']
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']


def lambda_handler(event, context):
    """
    Isolate a compromised EC2 instance by:
    1. Removing it from Auto Scaling Group (if applicable)
    2. Changing its security group to the isolation SG
    3. Creating a forensic EBS snapshot
    4. Notifying the security team via SNS
    """

    finding_id = None
    instance_id = None
    finding_type = None

    try:
        if 'detail' in event:
            detail = event['detail']
            finding_id = detail.get('id', 'unknown')

            if 'resource' in detail and 'instanceDetails' in detail['resource']:
                instance_id = detail['resource']['instanceDetails'].get('instanceId')
            elif 'resource' in detail and 'resources' in detail['resource']:
                for resource in detail['resource']['resources']:
                    if 'EC2' in resource.get('type', ''):
                        instance_id = resource.get('id', '').split('/')[-1]

            finding_type = detail.get('type', detail.get('Type', ['unknown']))
            if isinstance(finding_type, list):
                finding_type = finding_type[0] if finding_type else 'unknown'

        if not instance_id:
            print(f"No instance ID found in event: {json.dumps(event, default=str)}")
            return {'statusCode': 200, 'body': 'No instance ID found - skipping'}

        print(f"Isolating instance {instance_id} for finding {finding_id}")

        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = instance_info.get('Reservations', [])

        if not reservations:
            print(f"Instance {instance_id} not found - may have been terminated")
            return {'statusCode': 200, 'body': f'Instance {instance_id} not found'}

        instance = reservations[0]['Instances'][0]
        current_sgs = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]

        instance_name = ''
        for tag in instance.get('Tags', []):
            if tag['Key'] == 'Name':
                instance_name = tag['Value']

        asg_name = None
        for tag in instance.get('Tags', []):
            if tag['Key'] == 'aws:autoscaling:groupName':
                asg_name = tag['Value']

        actions_taken = []

        if asg_name:
            try:
                autoscaling = boto3.client('autoscaling')
                autoscaling.detach_instances(
                    AutoScalingGroupName=asg_name,
                    InstanceIds=[instance_id],
                    ShouldDecrementDesiredCapacity=False
                )
                actions_taken.append(f'Detached from ASG: {asg_name}')
                print(f"Detached instance {instance_id} from ASG {asg_name}")
            except Exception as e:
                print(f"Could not detach from ASG: {str(e)}")

        try:
            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[{'GroupId': ISOLATION_SG_ID}]
            )
            actions_taken.append(f'Security group changed to isolation SG: {ISOLATION_SG_ID}')
            print(f"Changed security group for {instance_id} to {ISOLATION_SG_ID}")
        except Exception as e:
            actions_taken.append(f'Failed to change security group: {str(e)}')
            print(f"Failed to change security group: {str(e)}")

        try:
            volumes = instance.get('BlockDeviceMappings', [])
            snapshot_ids = []
            for vol in volumes:
                if 'Ebs' in vol:
                    volume_id = vol['Ebs']['VolumeId']
                    snapshot = ec2.create_snapshot(
                        VolumeId=volume_id,
                        Description=f'Forensic snapshot for instance {instance_id} - finding {finding_id}',
                        TagSpecifications=[
                            {
                                'ResourceType': 'snapshot',
                                'Tags': [
                                    {'Key': 'Name', 'Value': f'forensic-{instance_id}'},
                                    {'Key': 'FindingId', 'Value': str(finding_id)},
                                    {'Key': 'IsolationTimestamp', 'Value': context.aws_request_id},
                                    {'Key': 'Type', 'Value': 'forensic'}
                                ]
                            }
                        ]
                    )
                    snapshot_ids.append(snapshot['SnapshotId'])
                    print(f"Created forensic snapshot {snapshot['SnapshotId']} for volume {volume_id}")
            actions_taken.append(f'Created {len(snapshot_ids)} forensic snapshots: {", ".join(snapshot_ids)}')
        except Exception as e:
            actions_taken.append(f'Failed to create snapshots: {str(e)}')
            print(f"Failed to create forensic snapshots: {str(e)}")

        message = {
            'FindingId': str(finding_id),
            'FindingType': str(finding_type),
            'InstanceId': instance_id,
            'InstanceName': instance_name,
            'InstanceState': instance['State']['Name'],
            'PreviousSecurityGroups': current_sgs,
            'IsolationSecurityGroup': ISOLATION_SG_ID,
            'AutoScalingGroup': asg_name,
            'ActionsTaken': actions_taken,
            'RequestId': context.aws_request_id
        }

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f'[SECURITY] EC2 Instance Isolated: {instance_id}',
            Message=json.dumps(message, indent=2)
        )
        print(f"Published isolation notification to SNS")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'instance_id': instance_id,
                'actions_taken': actions_taken
            })
        }

    except Exception as e:
        error_message = f"Error isolating instance: {str(e)}"
        print(error_message)

        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject='[ERROR] EC2 Isolation Failed',
                Message=json.dumps({
                    'error': error_message,
                    'event': event
                }, default=str)
            )
        except:
            pass

        return {
            'statusCode': 500,
            'body': json.dumps({'error': error_message})
        }