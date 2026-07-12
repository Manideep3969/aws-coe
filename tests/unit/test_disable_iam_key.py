"""Unit tests for the IAM key disable Lambda function."""

import json
import pytest
from unittest.mock import patch, MagicMock
from moto import mock_iam, mock_sns

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'incident-response', 'automation', 'src'))
import disable_iam_key


@mock_iam
@mock_sns
class TestDisableIamKey:
    """Test suite for IAM credential disable remediation."""

    def setup_method(self):
        """Set up test fixtures."""
        os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:ap-south-1:123456789012:npci-security-incidents'

    def test_handler_extracts_username_from_guardduty_event(self):
        """Test that username is correctly extracted from GuardDuty finding."""
        event = {
            'detail': {
                'id': 'test-finding-iam-001',
                'type': 'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration',
                'severity': 8,
                'resource': {
                    'accessKeyDetails': {
                        'userName': 'compromised-user',
                        'principalId': 'AIDA123456789',
                        'accessKeyId': 'AKIA1234567890ABCDEF'
                    }
                }
            }
        }
        context = MagicMock()
        context.aws_request_id = 'req-iam-001'

        with patch.object(disable_iam_key, 'iam', MagicMock()), \
             patch.object(disable_iam_key, 'sns', MagicMock()):

            mock_iam = disable_iam_key.iam
            mock_sns = disable_iam_key.sns

            mock_iam.get_user.return_value = {
                'User': {
                    'Arn': 'arn:aws:iam::123456789012:user/compromised-user',
                    'CreateDate': '2025-01-01T00:00:00Z'
                }
            }
            mock_iam.list_access_keys.return_value = {
                'AccessKeyMetadata': [
                    {'AccessKeyId': 'AKIA1234567890ABCDEF', 'Status': 'Active', 'CreateDate': '2025-01-01'},
                    {'AccessKeyId': 'AKIA0987654321ZYXWVU', 'Status': 'Active', 'CreateDate': '2025-02-01'}
                ]
            }
            mock_iam.update_access_key.return_value = {}
            mock_iam.delete_login_profile.side_effect = Exception('No login profile')
            mock_iam.list_mfa_devices.return_value = {'MFADevices': []}
            mock_iam.list_attached_user_policies.return_value = {'AttachedPolicies': []}
            mock_iam.list_user_policies.return_value = {'PolicyNames': []}
            mock_iam.put_user_policy.return_value = {}
            mock_sns.publish.return_value = {}

            result = disable_iam_key.lambda_handler(event, context)

            assert result['statusCode'] == 200
            body = json.loads(result['body'])
            assert body['disabled_keys'] == 2

    def test_handler_disables_all_active_access_keys(self):
        """Test that all active access keys are disabled."""
        event = {
            'detail': {
                'id': 'test-finding-iam-002',
                'type': 'UnauthorizedAccess:IAMUser/CompromisedKey',
                'severity': 9,
                'resource': {
                    'accessKeyDetails': {
                        'userName': 'test-user-multi-keys',
                        'principalId': 'AIDA987654321',
                        'accessKeyId': 'AKIA_MULTIKEY1'
                    }
                }
            }
        }
        context = MagicMock()
        context.aws_request_id = 'req-iam-002'

        with patch.object(disable_iam_key, 'iam', MagicMock()), \
             patch.object(disable_iam_key, 'sns', MagicMock()):

            mock_iam = disable_iam_key.iam
            mock_sns = disable_iam_key.sns

            mock_iam.get_user.return_value = {
                'User': {
                    'Arn': 'arn:aws:iam::123456789012:user/test-user-multi-keys',
                    'CreateDate': '2025-01-01T00:00:00Z'
                }
            }
            mock_iam.list_access_keys.return_value = {
                'AccessKeyMetadata': [
                    {'AccessKeyId': 'AKIA_KEY1', 'Status': 'Active'},
                    {'AccessKeyId': 'AKIA_KEY2', 'Status': 'Active'},
                    {'AccessKeyId': 'AKIA_KEY3', 'Status': 'Inactive'}
                ]
            }
            mock_iam.update_access_key.return_value = {}
            mock_iam.delete_login_profile.side_effect = disable_iam_key.iam.exceptions.NoSuchEntityException(
                {'Error': {'Code': 'NoSuchEntity'}}, 'delete_login_profile'
            )
            mock_iam.list_mfa_devices.return_value = {'MFADevices': []}
            mock_iam.list_attached_user_policies.return_value = {'AttachedPolicies': []}
            mock_iam.list_user_policies.return_value = {'PolicyNames': []}
            mock_iam.put_user_policy.return_value = {}
            mock_sns.publish.return_value = {}

            result = disable_iam_key.lambda_handler(event, context)

            assert mock_iam.update_access_key.call_count == 2

    def test_handler_removes_admin_policies(self):
        """Test that AdministratorAccess and FullAccess policies are detached."""
        event = {
            'detail': {
                'id': 'test-finding-iam-003',
                'type': 'UnauthorizedAccess:IAMUser/AdminKeyCompromised',
                'severity': 10,
                'resource': {
                    'accessKeyDetails': {
                        'userName': 'admin-user',
                        'principalId': 'AIDA_ADMIN123',
                        'accessKeyId': 'AKIA_ADMINKEY'
                    }
                }
            }
        }
        context = MagicMock()
        context.aws_request_id = 'req-iam-003'

        with patch.object(disable_iam_key, 'iam', MagicMock()), \
             patch.object(disable_iam_key, 'sns', MagicMock()):

            mock_iam = disable_iam_key.iam
            mock_sns = disable_iam_key.sns

            mock_iam.get_user.return_value = {
                'User': {
                    'Arn': 'arn:aws:iam::123456789012:user/admin-user',
                    'CreateDate': '2025-01-01T00:00:00Z'
                }
            }
            mock_iam.list_access_keys.return_value = {
                'AccessKeyMetadata': [
                    {'AccessKeyId': 'AKIA_ADMINKEY', 'Status': 'Active'}
                ]
            }
            mock_iam.update_access_key.return_value = {}
            mock_iam.delete_login_profile.side_effect = Exception('No login profile')
            mock_iam.list_mfa_devices.return_value = {'MFADevices': []}
            mock_iam.list_attached_user_policies.return_value = {
                'AttachedPolicies': [
                    {'PolicyName': 'AdministratorAccess', 'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'},
                    {'PolicyName': 'AmazonS3FullAccess', 'PolicyArn': 'arn:aws:iam::aws:policy/AmazonS3FullAccess'},
                    {'PolicyName': 'ReadOnlyAccess', 'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}
                ]
            }
            mock_iam.detach_user_policy.return_value = {}
            mock_iam.list_user_policies.return_value = {'PolicyNames': []}
            mock_iam.put_user_policy.return_value = {}
            mock_sns.publish.return_value = {}

            result = disable_iam_key.lambda_handler(event, context)

            assert mock_iam.detach_user_policy.call_count == 2

    def test_handler_applies_quarantine_deny_all_policy(self):
        """Test that a deny-all quarantine policy is applied."""
        event = {
            'detail': {
                'id': 'test-finding-iam-004',
                'type': 'UnauthorizedAccess:IAMUser/KeyExposed',
                'severity': 7,
                'resource': {
                    'accessKeyDetails': {
                        'userName': 'exposed-user',
                        'principalId': 'AIDA_EXPOSED',
                        'accessKeyId': 'AKIA_EXPOSED'
                    }
                }
            }
        }
        context = MagicMock()
        context.aws_request_id = 'req-iam-004'

        with patch.object(disable_iam_key, 'iam', MagicMock()), \
             patch.object(disable_iam_key, 'sns', MagicMock()):

            mock_iam = disable_iam_key.iam
            mock_sns = disable_iam_key.sns

            mock_iam.get_user.return_value = {
                'User': {
                    'Arn': 'arn:aws:iam::123456789012:user/exposed-user',
                    'CreateDate': '2025-01-01T00:00:00Z'
                }
            }
            mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
            mock_iam.delete_login_profile.side_effect = Exception('No login profile')
            mock_iam.list_mfa_devices.return_value = {'MFADevices': []}
            mock_iam.list_attached_user_policies.return_value = {'AttachedPolicies': []}
            mock_iam.list_user_policies.return_value = {'PolicyNames': []}
            mock_iam.put_user_policy.return_value = {}
            mock_sns.publish.return_value = {}

            disable_iam_key.lambda_handler(event, context)

            mock_iam.put_user_policy.assert_called_once()
            call_args = mock_iam.put_user_policy.call_args
            assert call_args.kwargs['PolicyName'] == 'QuarantineDenyAll'
            policy_doc = json.loads(call_args.kwargs['PolicyDocument'])
            assert policy_doc['Statement'][0]['Effect'] == 'Deny'
            assert policy_doc['Statement'][0]['Action'] == '*'
            assert policy_doc['Statement'][0]['Resource'] == '*'

    def test_handler_publishes_sns_notification(self):
        """Test that SNS notification is published after remediation."""
        event = {
            'detail': {
                'id': 'test-finding-iam-005',
                'type': 'UnauthorizedAccess:IAMUser/CompromiedCredentials',
                'severity': 8,
                'resource': {
                    'accessKeyDetails': {
                        'userName': 'notify-user',
                        'principalId': 'AIDA_NOTIFY',
                        'accessKeyId': 'AKIA_NOTIFY'
                    }
                }
            }
        }
        context = MagicMock()
        context.aws_request_id = 'req-iam-005'

        with patch.object(disable_iam_key, 'iam', MagicMock()), \
             patch.object(disable_iam_key, 'sns', MagicMock()):

            mock_iam = disable_iam_key.iam
            mock_sns = disable_iam_key.sns

            mock_iam.get_user.return_value = {
                'User': {
                    'Arn': 'arn:aws:iam::123456789012:user/notify-user',
                    'CreateDate': '2025-01-01T00:00:00Z'
                }
            }
            mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
            mock_iam.delete_login_profile.side_effect = Exception('No login profile')
            mock_iam.list_mfa_devices.return_value = {'MFADevices': []}
            mock_iam.list_attached_user_policies.return_value = {'AttachedPolicies': []}
            mock_iam.list_user_policies.return_value = {'PolicyNames': []}
            mock_iam.put_user_policy.return_value = {}
            mock_sns.publish.return_value = {}

            disable_iam_key.lambda_handler(event, context)

            mock_sns.publish.assert_called_once()
            call_args = mock_sns.publish.call_args
            assert 'IAM Credentials Disabled' in call_args.kwargs['Subject']

    def test_handler_handles_no_user_in_event(self):
        """Test graceful handling when no user is found in event."""
        event = {'detail': {}}
        context = MagicMock()
        context.aws_request_id = 'req-no-user'

        result = disable_iam_key.lambda_handler(event, context)
        assert result['statusCode'] == 200
        assert 'No user found' in result['body']

    def test_handler_handles_user_not_found(self):
        """Test graceful handling when user doesn't exist in IAM."""
        event = {
            'detail': {
                'id': 'test-finding-iam-006',
                'type': 'UnauthorizedAccess:IAMUser/DeletedUser',
                'severity': 5,
                'resource': {
                    'accessKeyDetails': {
                        'userName': 'deleted-user',
                        'principalId': 'AIDA_DELETED',
                        'accessKeyId': 'AKIA_DELETED'
                    }
                }
            }
        }
        context = MagicMock()
        context.aws_request_id = 'req-iam-006'

        with patch.object(disable_iam_key, 'iam', MagicMock()), \
             patch.object(disable_iam_key, 'sns', MagicMock()):

            mock_iam = disable_iam_key.iam

            class MockNoSuchEntityException(Exception):
                pass

            mock_iam.exceptions.NoSuchEntityException = MockNoSuchEntityException
            mock_iam.get_user.side_effect = MockNoSuchEntityException('User not found')

            result = disable_iam_key.lambda_handler(event, context)
            assert result['statusCode'] == 200