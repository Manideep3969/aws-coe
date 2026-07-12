"""Terraform configuration validation tests."""

import os
import re
import pytest

ROOT_DIR = os.path.join(os.path.dirname(__file__), '..', '..')

EXPECTED_MODULES = [
    'control-tower',
    'scp',
    'iam',
    'security',
    'security/guardduty',
    'security/security-hub',
    'security/waf',
    'security/inspector',
    'networking',
    'networking/vpc-flow-logs',
    'networking/network-firewall',
    'networking/segmentation',
    'data-protection',
    'data-protection/kms',
    'data-protection/s3-access-logs',
    'data-protection/data-classification',
    'incident-response',
    'incident-response/automation',
    'backup',
    'backup/policies',
]


class TestTerraformStructure:
    """Validate Terraform module structure and conventions."""

    @pytest.fixture(params=EXPECTED_MODULES)
    def module_dir(self, request):
        return os.path.join(ROOT_DIR, request.param)

    def test_module_has_main_tf(self, module_dir):
        """Test that every module has a main.tf file."""
        main_tf = os.path.join(module_dir, 'main.tf')
        assert os.path.exists(main_tf), f"{module_dir} missing main.tf"

    def test_main_tf_not_empty(self, module_dir):
        """Test that main.tf is not empty."""
        main_tf = os.path.join(module_dir, 'main.tf')
        if os.path.exists(main_tf):
            with open(main_tf, 'r') as f:
                content = f.read()
            assert len(content.strip()) > 0, f"{main_tf} is empty"

    def test_resource_names_start_with_npci(self, module_dir):
        """Test that resource names follow the npci- naming convention."""
        main_tf = os.path.join(module_dir, 'main.tf')
        if not os.path.exists(main_tf):
            return

        with open(main_tf, 'r') as f:
            content = f.read()

        resource_blocks = re.findall(r'resource\s+"(\w+)"\s+"(\w+)"', content)
        for resource_type, resource_name in resource_blocks:
            if resource_type in ['aws_s3_bucket', 'aws_kms_key', 'aws_kms_alias',
                                  'aws_iam_policy', 'aws_iam_role', 'aws_lambda_function',
                                  'aws_cloudwatch_event_rule', 'aws_security_group',
                                  'aws_networkfirewall_firewall', 'aws_wafv2_web_acl',
                                  'aws_backup_vault', 'aws_backup_plan',
                                  'aws_flow_log', 'aws_guardduty_detector',
                                  'aws_sns_topic', 'aws_cloudwatch_log_group']:
                assert resource_name.startswith('npci_') or resource_name.startswith('npci-'), \
                    f"{module_dir}: {resource_type}.{resource_name} should start with 'npci_' or 'npci-'"

    def test_no_hardcoded_secrets(self, module_dir):
        """Test that no hardcoded secrets or passwords exist."""
        main_tf = os.path.join(module_dir, 'main.tf')
        if not os.path.exists(main_tf):
            return

        with open(main_tf, 'r') as f:
            content = f.read()

        secret_patterns = [
            r'password\s*=\s*"[^"$]',
            r'secret\s*=\s*"[^"$]',
            r'api_key\s*=\s*"[^"$]',
            r'access_key\s*=\s*"[^"$]',
            r'AKIA[A-Z0-9]{16}',
        ]

        for pattern in secret_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            assert len(matches) == 0, \
                f"{module_dir}: Potential hardcoded secret found: {matches}"

    def test_tags_applied(self, module_dir):
        """Test that resources have tags applied."""
        main_tf = os.path.join(module_dir, 'main.tf')
        if not os.path.exists(main_tf):
            return

        with open(main_tf, 'r') as f:
            content = f.read()

        if 'resource "' in content:
            taggable_types = [
                'aws_s3_bucket', 'aws_kms_key', 'aws_iam_policy', 'aws_iam_role',
                'aws_lambda_function', 'aws_cloudwatch_event_rule', 'aws_security_group',
                'aws_networkfirewall_firewall', 'aws_wafv2_web_acl',
                'aws_backup_vault', 'aws_backup_plan', 'aws_guardduty_detector',
                'aws_sns_topic', 'aws_cloudwatch_log_group', 'aws_config_config_rule',
                'aws_organizations_policy', 'aws_accessanalyzer_analyzer',
                'aws_inspector2_filter',
            ]
            for res_type in taggable_types:
                if f'resource "{res_type}"' in content:
                    assert 'tags' in content, \
                        f"{module_dir}: {res_type} resource found but no tags applied"


class TestRootModule:
    """Validate root module configuration."""

    def test_main_tf_exists(self):
        assert os.path.exists(os.path.join(ROOT_DIR, 'main.tf'))

    def test_variables_tf_exists(self):
        assert os.path.exists(os.path.join(ROOT_DIR, 'variables.tf'))

    def test_outputs_tf_exists(self):
        assert os.path.exists(os.path.join(ROOT_DIR, 'outputs.tf'))

    def test_gitignore_exists(self):
        assert os.path.exists(os.path.join(ROOT_DIR, '.gitignore'))

    def test_makefile_exists(self):
        assert os.path.exists(os.path.join(ROOT_DIR, 'Makefile'))

    def test_backend_configured(self):
        main_tf = os.path.join(ROOT_DIR, 'main.tf')
        with open(main_tf, 'r') as f:
            content = f.read()
        assert 'backend' in content, "Terraform backend not configured"

    def test_required_version_specified(self):
        main_tf = os.path.join(ROOT_DIR, 'main.tf')
        with open(main_tf, 'r') as f:
            content = f.read()
        assert 'required_version' in content, "Terraform required_version not specified"

    def test_provider_version_constrained(self):
        main_tf = os.path.join(ROOT_DIR, 'main.tf')
        with open(main_tf, 'r') as f:
            content = f.read()
        assert 'version' in content or 'source' in content, "Provider version not constrained"


class TestSCPPolicyFiles:
    """Validate SCP policy JSON files."""

    POLICIES_DIR = os.path.join(ROOT_DIR, 'scp', 'policies')

    EXPECTED_POLICIES = [
        'root-protection.json',
        'region-lock.json',
        'security-service-protection.json',
        'encryption-enforcement.json',
        'public-access-prevention.json',
        'network-protection.json',
    ]

    def test_all_policy_files_exist(self):
        for policy in self.EXPECTED_POLICIES:
            filepath = os.path.join(self.POLICIES_DIR, policy)
            assert os.path.exists(filepath), f"Missing policy file: {policy}"

    def test_no_extra_policy_files(self):
        files = [f for f in os.listdir(self.POLIES_DIR) if f.endswith('.json')]
        for f in files:
            assert f in self.EXPECTED_POLICIES, f"Unexpected policy file: {f}"


class TestLambdaSourceFiles:
    """Validate Lambda function source files."""

    SRC_DIR = os.path.join(ROOT_DIR, 'incident-response', 'automation', 'src')

    EXPECTED_FILES = [
        'isolate_ec2.py',
        'disable_iam_key.py',
    ]

    def test_lambda_source_files_exist(self):
        for src_file in self.EXPECTED_FILES:
            filepath = os.path.join(self.SRC_DIR, src_file)
            assert os.path.exists(filepath), f"Missing Lambda source: {src_file}"

    def test_lambda_handler_defined(self):
        for src_file in self.EXPECTED_FILES:
            filepath = os.path.join(self.SRC_DIR, src_file)
            with open(filepath, 'r') as f:
                content = f.read()
            assert 'def lambda_handler(' in content, \
                f"{src_file} missing lambda_handler function"

    def test_lambda_has_error_handling(self):
        for src_file in self.EXPECTED_FILES:
            filepath = os.path.join(self.SRC_DIR, src_file)
            with open(filepath, 'r') as f:
                content = f.read()
            assert 'try:' in content, f"{src_file} missing try/except error handling"
            assert 'except' in content, f"{src_file} missing except block"

    def test_lambda_has_sns_notification(self):
        for src_file in self.EXPECTED_FILES:
            filepath = os.path.join(self.SRC_DIR, src_file)
            with open(filepath, 'r') as f:
                content = f.read()
            assert 'sns.publish' in content, f"{src_file} missing SNS notification"