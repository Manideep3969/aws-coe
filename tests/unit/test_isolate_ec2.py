"""Unit tests for the EC2 isolation Lambda function."""

import json
import pytest
from unittest.mock import patch, MagicMock, patch
from moto import mock_ec2, mock_sns, mock_ssm, mock_iam

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'incident-response', 'automation', 'src'))
import isolate_ec2


@mock_ec2
@mock_sns
class TestIsolateEc2:
    """Test suite for EC2 isolation remediation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_ec2_client = MagicMock()
        self.mock_sns_client = MagicMock()
        self.mock_ssm_client = MagicMock()

        os.environ['ISOLATION_SG_ID'] = 'sg-isolation123'
        os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:ap-south-1:123456789012:npci-security-incidents'

    def test_handler_extracts_instance_id_from_guardduty_event(self):
        """Test that instance ID is correctly extracted from GuardDuty finding."""
        event = {
            'detail': {
                'id': 'test-finding-123',
                'type': 'Backdoor:EC2/CryptoCurrencyMiner',
                'resource': {
                    'instanceDetails': {
                        'instanceId': 'i-1234567890abcdef0'
                    }
                }
            }
        }
        context = MagicMock()
        context.aws_request_id = 'req-123'

        with patch.object(isolate_ec2, 'ec2', self.mock_ec2_client), \
             patch.object(isolate_ec2, 'sns', self.mock_sns_client):

            self.mock_ec2_client.describe_instances.return_value = {
                'Reservations': [{
                    'Instances': [{
                        'InstanceId': 'i-1234567890abcdef0',
                        'State': {'Name': 'running'},
                        'SecurityGroups': [{'GroupId': 'sg-original'}],
                        'BlockDeviceMappings': [],
                        'Tags': [{'Key': 'Name', 'Value': 'test-instance'}]
                    }]
                }]
            }
            self.mock_ec2_client.modify_instance_attribute.return_value = {}
            self.mock_sns_client.publish.return_value = {}

            result = isolate_ec2.lambda_handler(event, context)

            assert result['statusCode'] == 200

    def test_handler_returns_200_when_no_instance_id(self):
        """Test graceful handling when no instance ID found in event."""
        event = {'detail': {}}
        context = MagicMock()
        context.aws_request_id = 'req-123'

        result = isolate_ec2.lambda_handler(event, context)
        assert result['statusCode'] == 200
        assert 'No instance ID found' in result['body']

    def test_handler_changes_security_group_to_isolation_sg(self):
        """Test that security group is changed to isolation SG."""
        event = {
            'detail': {
                'id': 'test-finding-456',
                'type': 'Backdoor:EC2/PhishingDomain',
                'resource': {
                    'instanceDetails': {
                        'instanceId': 'i-testinstance1'
                    }
                }
            }
        }
        context = MagicMock()
        context.aws_request_id = 'req-456'

        with patch.object(isolate_ec2, 'ec2', self.mock_ec2_client), \
             patch.object(isolate_ec2, 'sns', self.mock_sns_client):

            self.mock_ec2_client.describe_instances.return_value = {
                'Reservations': [{
                    'Instances': [{
                        'InstanceId': 'i-testinstance1',
                        'State': {'Name': 'running'},
                        'SecurityGroups': [{'GroupId': 'sg-original'}],
                        'BlockDeviceMappings': [],
                        'Tags': [{'Key': 'Name', 'Value': 'compromised-instance'}]
                    }]
                }]
            }
            self.mock_ec2_client.modify_instance_attribute.return_value = {}
            self.mock_sns_client.publish.return_value = {}

            isolate_ec2.lambda_handler(event, context)

            self.mock_ec2_client.modify_instance_attribute.assert_called_once()
            call_args = self.mock_ec2_client.modify_instance_attribute.call_args
            assert call_args.kwargs['InstanceId'] == 'i-testinstance1'
            assert call_args.kwargs['Groups'] == [{'GroupId': 'sg-isolation123'}]

    def test_handler_creates_forensic_snapshots(self):
        """Test that EBS snapshots are created for forensics."""
        event = {
            'detail': {
                'id': 'test-finding-789',
                'type': 'Trojan:EC2/PhishingDomain',
                'resource': {
                    'instanceDetails': {
                        'instanceId': 'i-snaptest'
                    }
                }
            }
        }
        context = MagicMock()
        context.aws_request_id = 'req-789'

        with patch.object(isolate_ec2, 'ec2', self.mock_ec2_client), \
             patch.object(isolate_ec2, 'sns', self.mock_sns_client):

            self.mock_ec2_client.describe_instances.return_value = {
                'Reservations': [{
                    'Instances': [{
                        'InstanceId': 'i-snaptest',
                        'State': {'Name': 'running'},
                        'SecurityGroups': [{'GroupId': 'sg-original'}],
                        'BlockDeviceMappings': [{
                            'Ebs': {'VolumeId': 'vol-123456'}
                        }],
                        'Tags': [{'Key': 'Name', 'Value': 'test-snap'}]
                    }]
                }]
            }
            self.mock_ec2_client.modify_instance_attribute.return_value = {}
            self.mock_ec2_client.create_snapshot.return_value = {
                'SnapshotId': 'snap-test123'
            }
            self.mock_sns_client.publish.return_value = {}

            result = isolate_ec2.lambda_handler(event, context)

            self.mock_ec2_client.create_snapshot.assert_called_once()

    def test_handler_publishes_sns_notification(self):
        """Test that SNS notification is published after isolation."""
        event = {
            'detail': {
                'id': 'test-finding-sns',
                'type': 'UnauthorizedAccess:EC2/SSHBruteForce',
                'resource': {
                    'instanceDetails': {
                        'instanceId': 'i-snstest'
                    }
                }
            }
        }
        context = MagicMock()
        context.aws_request_id = 'req-sns'

        with patch.object(isolate_ec2, 'ec2', self.mock_ec2_client), \
             patch.object(isolate_ec2, 'sns', self.mock_sns_client):

            self.mock_ec2_client.describe_instances.return_value = {
                'Reservations': [{
                    'Instances': [{
                        'InstanceId': 'i-snstest',
                        'State': {'Name': 'running'},
                        'SecurityGroups': [{'GroupId': 'sg-original'}],
                        'BlockDeviceMappings': [],
                        'Tags': [{'Key': 'Name', 'Value': 'sns-test-instance'}]
                    }]
                }]
            }
            self.mock_ec2_client.modify_instance_attribute.return_value = {}
            self.mock_sns_client.publish.return_value = {}

            isolate_ec2.lambda_handler(event, context)

            self.mock_sns_client.publish.assert_called_once()
            call_args = self.mock_sns_client.publish.call_args
            assert 'EC2 Instance Isolated' in call_args.kwargs['Subject']

    def test_handler_handles_instance_not_found(self):
        """Test graceful handling when instance doesn't exist."""
        event = {
            'detail': {
                'id': 'test-finding-notfound',
                'type': 'Recon:EC2/PortProbeUnprotectedPort',
                'resource': {
                    'instanceDetails': {
                        'instanceId': 'i-notfound'
                    }
                }
            }
        }
        context = MagicMock()
        context.aws_request_id = 'req-notfound'

        with patch.object(isolate_ec2, 'ec2', self.mock_ec2_client), \
             patch.object(isolate_ec2, 'sns', self.mock_sns_client):

            self.mock_ec2_client.describe_instances.return_value = {
                'Reservations': []
            }

            result = isolate_ec2.lambda_handler(event, context)
            assert result['statusCode'] == 200
            assert 'not found' in result['body']

    def test_handler_handles_ec2_api_error(self):
        """Test error handling when EC2 API calls fail."""
        event = {
            'detail': {
                'id': 'test-finding-error',
                'type': 'Backdoor:EC2/DNSRequest',
                'resource': {
                    'instanceDetails': {
                        'instanceId': 'i-errortest'
                    }
                }
            }
        }
        context = MagicMock()
        context.aws_request_id = 'req-error'

        with patch.object(isolate_ec2, 'ec2', self.mock_ec2_client), \
             patch.object(isolate_ec2, 'sns', self.mock_sns_client):

            self.mock_ec2_client.describe_instances.side_effect = Exception('EC2 API Error')

            result = isolate_ec2.lambda_handler(event, context)
            assert result['statusCode'] == 500