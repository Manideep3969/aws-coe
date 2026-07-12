import json
import boto3
import os

iam = boto3.client('iam')
sns = boto3.client('sns')

SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']


def lambda_handler(event, context):
    """
    Disable compromised IAM access keys by:
    1. Identifying the user from the GuardDuty finding
    2. Disabling all active access keys for that user
    3. Detaching overly permissive policies
    4. Notifying the security team via SNS
    """

    finding_id = None
    user_name = None
    finding_type = None
    finding_severity = None

    try:
        if 'detail' in event:
            detail = event['detail']
            finding_id = detail.get('id', 'unknown')
            finding_type = detail.get('type', detail.get('Type', ['unknown']))
            finding_severity = detail.get('severity', detail.get('Severity', 'unknown'))

            if isinstance(finding_type, list):
                finding_type = finding_type[0] if finding_type else 'unknown'

            if 'resource' in detail and 'accessKeyDetails' in detail['resource']:
                access_key_info = detail['resource']['accessKeyDetails']
                user_name = access_key_info.get('userName')
                principal_id = access_key_info.get('principalId')
                access_key_id = access_key_info.get('accessKeyId')

        if not user_name:
            if 'resources' in event.get('detail', {}):
                for resource in event['detail']['resources']:
                    if 'iam' in resource.get('type', '').lower():
                        user_arn = resource.get('id', '')
                        user_name = user_arn.split('/')[-1]

        if not user_name:
            print(f"No user found in event: {json.dumps(event, default=str)}")
            return {'statusCode': 200, 'body': 'No user found - skipping'}

        print(f"Processing compromised credentials for user: {user_name}, finding: {finding_id}")

        actions_taken = []
        disabled_keys = []
        removed_policies = []

        try:
            user_info = iam.get_user(UserName=user_name)
            user_arn = user_info['User']['Arn']
            user_created = user_info['User']['CreateDate'].isoformat()
        except iam.exceptions.NoSuchEntityException:
            print(f"User {user_name} not found - may have been deleted")
            return {'statusCode': 200, 'body': f'User {user_name} not found'}
        except Exception as e:
            print(f"Error getting user info: {str(e)}")
            user_arn = f'arn:aws:iam::*:user/{user_name}'
            user_created = 'unknown'

        try:
            access_keys = iam.list_access_keys(UserName=user_name)
            for key in access_keys['AccessKeyMetadata']:
                if key['Status'] == 'Active':
                    iam.update_access_key(
                        UserName=user_name,
                        AccessKeyId=key['AccessKeyId'],
                        Status='Inactive'
                    )
                    disabled_keys.append(key['AccessKeyId'])
                    print(f"Disabled access key {key['AccessKeyId'][:4]}...{key['AccessKeyId'][-4:]} for user {user_name}")

            actions_taken.append(f'Disabled {len(disabled_keys)} active access keys')
        except Exception as e:
            actions_taken.append(f'Failed to disable access keys: {str(e)}')
            print(f"Error disabling access keys: {str(e)}")

        try:
            login_profile = iam.get_login_profile(UserName=user_name)
            iam.delete_login_profile(UserName=user_name)
            actions_taken.append('Deleted console login profile (prevents console access)')
            print(f"Deleted login profile for user {user_name}")
        except iam.exceptions.NoSuchEntityException:
            actions_taken.append('No console login profile found (API-only user)')
        except Exception as e:
            actions_taken.append(f'Could not delete login profile: {str(e)}')
            print(f"Could not delete login profile: {str(e)}")

        try:
            mfa_devices = iam.list_mfa_devices(UserName=user_name)
            if mfa_devices['MFADevices']:
                for device in mfa_devices['MFADevices']:
                    iam.deactivate_mfa_device(
                        UserName=user_name,
                        SerialNumber=device['SerialNumber']
                    )
                actions_taken.append(f'Deactivated {len(mfa_devices["MFADevices"])} MFA device(s)')
                print(f"Deactivated MFA devices for user {user_name}")
            else:
                actions_taken.append('No MFA devices found')
        except Exception as e:
            actions_taken.append(f'Could not manage MFA devices: {str(e)}')
            print(f"Error managing MFA devices: {str(e)}")

        try:
            attached_policies = iam.list_attached_user_policies(UserName=user_name)
            admin_policy_arns = []
            for policy in attached_policies['AttachedPolicies']:
                if 'AdministratorAccess' in policy['PolicyName'] or 'FullAccess' in policy['PolicyName']:
                    admin_policy_arns.append(policy['PolicyArn'])
                    iam.detach_user_policy(
                        UserName=user_name,
                        PolicyArn=policy['PolicyArn']
                    )
                    removed_policies.append(policy['PolicyName'])

            if admin_policy_arns:
                actions_taken.append(f'Removed admin policies: {", ".join(removed_policies)}')
                print(f"Removed admin policies from user {user_name}: {removed_policies}')
        except Exception as e:
            actions_taken.append(f'Could not review attached policies: {str(e)}')
            print(f"Error reviewing policies: {str(e)}")

        try:
            inline_policies = iam.list_user_policies(UserName=user_name)
            for policy_name in inline_policies['PolicyNames']:
                iam.delete_user_policy(
                    UserName=user_name,
                    PolicyName=policy_name
                )
            if inline_policies['PolicyNames']:
                actions_taken.append(f'Deleted {len(inline_policies["PolicyNames"])} inline policy/policies')
                print(f"Deleted inline policies for user {user_name}")
        except Exception as e:
            actions_taken.append(f'Could not delete inline policies: {str(e)}')
            print(f"Error deleting inline policies: {str(e)}")

        try:
            iam.put_user_policy(
                UserName=user_name,
                PolicyName='QuarantineDenyAll',
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "QuarantineDenyAll",
                            "Effect": "Deny",
                            "Action": "*",
                            "Resource": "*"
                        }
                    ]
                })
            )
            actions_taken.append('Applied quarantine deny-all policy')
            print(f"Applied quarantine policy to user {user_name}")
        except Exception as e:
            actions_taken.append(f'Could not apply quarantine policy: {str(e)}')
            print(f"Error applying quarantine policy: {str(e)}")

        message = {
            'FindingId': str(finding_id),
            'FindingType': str(finding_type),
            'FindingSeverity': str(finding_severity),
            'UserName': user_name,
            'UserArn': user_arn,
            'UserCreated': user_created,
            'DisabledAccessKeys': disabled_keys,
            'RemovedPolicies': removed_policies,
            'ActionsTaken': actions_taken,
            'RequestId': context.aws_request_id,
            'NextSteps': [
                f'Investigate actions taken by {user_name} in CloudTrail',
                f'Review GuardDuty finding {finding_id} for full details',
                'If legitimate, restore access via break-glass procedure',
                'Document incident in incident tracker'
            ]
        }

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f'[SECURITY] IAM Credentials Disabled: {user_name}',
            Message=json.dumps(message, indent=2)
        )
        print(f"Published credential disable notification to SNS")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'user_name': user_name,
                'disabled_keys': len(disabled_keys),
                'actions_taken': actions_taken
            })
        }

    except Exception as e:
        error_message = f"Error disabling IAM credentials: {str(e)}"
        print(error_message)

        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject='[ERROR] IAM Credential Disable Failed',
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