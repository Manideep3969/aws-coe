"""SCP policy validation tests."""

import json
import pytest
import os

POLICIES_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'scp', 'policies')

EXPECTED_POLICIES = [
    'root-protection.json',
    'region-lock.json',
    'security-service-protection.json',
    'encryption-enforcement.json',
    'public-access-prevention.json',
    'network-protection.json',
]


class TestSCPPolicies:
    """Validate all SCP JSON policies."""

    @pytest.fixture(params=EXPECTED_POLICIES)
    def policy_file(self, request):
        return request.param

    def test_policy_file_exists(self, policy_file):
        """Test that all expected policy files exist."""
        filepath = os.path.join(POLICIES_DIR, policy_file)
        assert os.path.exists(filepath), f"Policy file {policy_file} not found"

    def test_policy_is_valid_json(self, policy_file):
        """Test that all policy files contain valid JSON."""
        filepath = os.path.join(POLICIES_DIR, policy_file)
        with open(filepath, 'r') as f:
            try:
                policy = json.load(f)
            except json.JSONDecodeError as e:
                pytest.fail(f"Invalid JSON in {policy_file}: {e}")

    def test_policy_has_required_fields(self, policy_file):
        """Test that policies have Version and Statement fields."""
        filepath = os.path.join(POLICIES_DIR, policy_file)
        with open(filepath, 'r') as f:
            policy = json.load(f)

        assert 'Version' in policy, f"{policy_file} missing Version field"
        assert policy['Version'] == '2012-10-17', f"{policy_file} has invalid Version"
        assert 'Statement' in policy, f"{policy_file} missing Statement field"
        assert isinstance(policy['Statement'], list), f"{policy_file} Statement must be a list"
        assert len(policy['Statement']) > 0, f"{policy_file} must have at least one Statement"

    def test_each_statement_has_required_fields(self, policy_file):
        """Test that each Statement has Sid, Effect, and Action."""
        filepath = os.path.join(POLICIES_DIR, policy_file)
        with open(filepath, 'r') as f:
            policy = json.load(f)

        for statement in policy['Statement']:
            assert 'Sid' in statement, f"{policy_file}: Statement missing Sid"
            assert 'Effect' in statement, f"{policy_file}: Statement missing Effect"
            assert statement['Effect'] in ['Allow', 'Deny'], \
                f"{policy_file}: Effect must be Allow or Deny, got {statement['Effect']}"

    def test_deny_policies_have_condition_or_resource(self, policy_file):
        """Test that Deny statements have either Condition or Resource constraints."""
        filepath = os.path.join(POLICIES_DIR, policy_file)
        with open(filepath, 'r') as f:
            policy = json.load(f)

        for statement in policy['Statement']:
            if statement['Effect'] == 'Deny':
                has_resource = 'Resource' in statement
                has_condition = 'Condition' in statement
                assert has_resource or has_condition, \
                    f"{policy_file}: Deny statement '{statement['Sid']}' must have Resource or Condition"

    def test_no_star_resource_in_allow_statements(self, policy_file):
        """Test that Allow statements don't use Resource: * (overly permissive)."""
        filepath = os.path.join(POLICIES_DIR, policy_file)
        with open(filepath, 'r') as f:
            policy = json.load(f)

        for statement in policy['Statement']:
            if statement['Effect'] == 'Allow':
                resource = statement.get('Resource', '')
                if isinstance(resource, str):
                    assert resource != '*', \
                        f"{policy_file}: Allow statement '{statement['Sid']}' uses Resource: *"
                elif isinstance(resource, list):
                    assert '*' not in resource, \
                        f"{policy_file}: Allow statement '{statement['Sid']}' uses Resource: *"


class TestRootProtectionPolicy:
    """Specific tests for the root protection SCP."""

    def test_deny_root_access_key_creation(self):
        filepath = os.path.join(POLICIES_DIR, 'root-protection.json')
        with open(filepath, 'r') as f:
            policy = json.load(f)

        sids = [s['Sid'] for s in policy['Statement']]
        assert 'DenyRootAccessKeyCreation' in sids

    def test_deny_root_user_actions(self):
        filepath = os.path.join(POLICIES_DIR, 'root-protection.json')
        with open(filepath, 'r') as f:
            policy = json.load(f)

        sids = [s['Sid'] for s in policy['Statement']]
        assert 'DenyRootUserActions' in sids


class TestRegionLockPolicy:
    """Specific tests for the region lock SCP."""

    def test_region_lock_has_not_action(self):
        filepath = os.path.join(POLICIES_DIR, 'region-lock.json')
        with open(filepath, 'r') as f:
            policy = json.load(f)

        statement = policy['Statement'][0]
        assert 'NotAction' in statement, "Region lock should use NotAction"

    def test_region_lock_has_condition(self):
        filepath = os.path.join(POLICIES_DIR, 'region-lock.json')
        with open(filepath, 'r') as f:
            policy = json.load(f)

        statement = policy['Statement'][0]
        assert 'Condition' in statement, "Region lock must have Condition"
        assert 'StringNotEquals' in statement['Condition']


class TestEncryptionPolicy:
    """Specific tests for the encryption enforcement SCP."""

    def test_s3_encryption_required(self):
        filepath = os.path.join(POLICIES_DIR, 'encryption-enforcement.json')
        with open(filepath, 'r') as f:
            policy = json.load(f)

        sids = [s['Sid'] for s in policy['Statement']]
        assert 'DenyUnencryptedS3' in sids

    def test_ebs_encryption_required(self):
        filepath = os.path.join(POLICIES_DIR, 'encryption-enforcement.json')
        with open(filepath, 'r') as f:
            policy = json.load(f)

        sids = [s['Sid'] for s in policy['Statement']]
        assert 'DenyUnencryptedEBS' in sids

    def test_rds_encryption_required(self):
        filepath = os.path.join(POLICIES_DIR, 'encryption-enforcement.json')
        with open(filepath, 'r') as f:
            policy = json.load(f)

        sids = [s['Sid'] for s in policy['Statement']]
        assert 'DenyUnencryptedRDS' in sids