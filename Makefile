# AWS CoE - Makefile
# Top-level orchestrator for all infrastructure modules
#
# Usage:
#   make init          - Initialize all Terraform modules
#   make plan          - Plan all modules
#   make apply         - Apply all modules
#   make destroy       - Destroy all infrastructure
#   make validate      - Validate all modules
#   make lint          - Run terraform fmt + validate
#   make check         - Full validation + security scan
#   make <module>-init - Initialize specific module
#   make <module>-plan - Plan specific module
#   make <module>-apply - Apply specific module

SHELL := /bin/bash
TF    := terraform
AWS_REGION := ap-south-1
TF_VARS    ?= terraform.tfvars

# Module directories in deployment order
MODULES := control-tower scp iam security networking data-protection incident-response backup

# Colors for output
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
NC     := \033[0m

.PHONY: all init plan apply destroy validate lint fmt check clean \
        $(addsuffix -init,$(MODULES)) $(addsuffix -plan,$(MODULES)) \
        $(addsuffix -apply,$(MODULES)) $(addsuffix -destroy,$(MODULES)) \
        $(addsuffix -validate,$(MODULES)) $(addsuffix -fmt,$(MODULES)) \
        help

# ============================================================================
# Default target
# ============================================================================

help: ## Show this help message
	@echo "$(GREEN)AWS Center of Excellence - Makefile Help$(NC)"
	@echo ""
	@echo "$(YELLOW)Top-level targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Module-specific targets:$(NC)"
	@for mod in $(MODULES); do \
		echo "  $(GREEN)$$mod-init$(NC)       Initialize $$mod"; \
		echo "  $(GREEN)$$mod-plan$(NC)       Plan $$mod"; \
		echo "  $(GREEN)$$mod-apply$(NC)      Apply $$mod"; \
		echo "  $(GREEN)$$mod-destroy$(NC)     Destroy $$mod"; \
		echo "  $(GREEN)$$mod-validate$(NC)    Validate $$mod"; \
		echo "  $(GREEN)$$mod-fmt$(NC)         Format $$mod"; \
	done
	@echo ""
	@echo "$(YELLOW)Deployment order:$(NC)"
	@for mod in $(MODULES); do \
		echo "  $$mod"; \
	done

# ============================================================================
# Top-level targets
# ============================================================================

all: init plan ## Initialize and plan all modules

init: $(addsuffix -init,$(MODULES)) ## Initialize all Terraform modules

plan: $(addsuffix -plan,$(MODULES)) ## Plan all Terraform modules

apply: ## Apply all Terraform modules (asks for confirmation)
	@echo "$(RED)WARNING: This will apply ALL Terraform modules in order.$(NC)"
	@echo "$(RED)This action will create/modify real AWS resources.$(NC)"
	@read -p "Are you sure you want to continue? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	@for mod in $(MODULES); do \
		echo "$(GREEN)Applying $$mod...$(NC)"; \
		$(MAKE) $$mod-apply; \
	done

destroy: ## Destroy all infrastructure (asks for confirmation)
	@echo "$(RED)WARNING: This will DESTROY all infrastructure.$(NC)"
	@echo "$(RED)This action is IRREVERSIBLE.$(NC)"
	@read -p "Type 'DESTROY' to confirm: " confirm && [ "$$confirm" = "DESTROY" ] || exit 1
	@for mod in $(addsuffix -destroy,$(shell echo $(MODULES) | tr ' ' '\n' | tac | tr '\n' ' ')); do \
		echo "$(RED)Destroying $${mod%-destroy}...$(NC)"; \
		$(MAKE) $$mod; \
	done

validate: $(addsuffix -validate,$(MODULES)) ## Validate all Terraform modules

fmt: $(addsuffix -fmt,$(MODULES)) ## Format all Terraform files

lint: fmt validate ## Format and validate all modules

check: lint ## Full validation pipeline (fmt + validate + tfsec)

clean: ## Remove .terraform directories and .tfstate files
	@echo "$(YELLOW)Cleaning .terraform directories and state files...$(NC)"
	find . -type d -name '.terraform' -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.tfstate' -delete 2>/dev/null || true
	find . -type f -name '*.tfstate.backup' -delete 2>/dev/null || true
	find . -type f -name '.terraform.lock.hcl' -delete 2>/dev/null || true
	@echo "$(GREEN)Clean complete.$(NC)"

# ============================================================================
# Phase-specific targets (deploy by SOC remediation phase)
# ============================================================================

phase1-init: control-tower-init scp-init iam-init ## Initialize Phase 1 modules (0-7 days)
	@echo "$(GREEN)Phase 1 initialization complete.$(NC)"

phase1-plan: control-tower-plan scp-plan iam-plan ## Plan Phase 1 modules
	@echo "$(GREEN)Phase 1 plan complete.$(NC)"

phase1-apply: control-tower-apply scp-apply iam-apply ## Apply Phase 1 modules
	@echo "$(GREEN)Phase 1 apply complete.$(NC)"

phase2-init: security-init networking-init ## Initialize Phase 2 modules (7-21 days)
	@echo "$(GREEN)Phase 2 initialization complete.$(NC)"

phase2-plan: security-plan networking-plan ## Plan Phase 2 modules
	@echo "$(GREEN)Phase 2 plan complete.$(NC)"

phase2-apply: security-apply networking-apply ## Apply Phase 2 modules
	@echo "$(GREEN)Phase 2 apply complete.$(NC)"

phase3-init: data-protection-init incident-response-init backup-init ## Initialize Phase 3 modules (21-30 days)
	@echo "$(GREEN)Phase 3 initialization complete.$(NC)"

phase3-plan: data-protection-plan incident-response-plan backup-plan ## Plan Phase 3 modules
	@echo "$(GREEN)Phase 3 plan complete.$(NC)"

phase3-apply: data-protection-apply incident-response-apply backup-apply ## Apply Phase 3 modules
	@echo "$(GREEN)Phase 3 apply complete.$(NC)"

# ============================================================================
# Per-module targets
# ============================================================================

# Control Tower
control-tower-init:
	@echo "$(GREEN)Initializing control-tower...$(NC)"
	cd control-tower && $(TF) init

control-tower-plan:
	@echo "$(GREEN)Planning control-tower...$(NC)"
	cd control-tower && $(TF) plan -var-file=$(TF_VARS)

control-tower-apply:
	@echo "$(GREEN)Applying control-tower...$(NC)"
	cd control-tower && $(TF) apply -var-file=$(TF_VARS) -auto-approve

control-tower-destroy:
	@echo "$(RED)Destroying control-tower...$(NC)"
	cd control-tower && $(TF) destroy -var-file=$(TF_VARS) -auto-approve

control-tower-validate:
	cd control-tower && $(TF) validate

control-tower-fmt:
	cd control-tower && $(TF) fmt -recursive -check

# SCP
scp-init:
	@echo "$(GREEN)Initializing scp...$(NC)"
	cd scp && $(TF) init

scp-plan:
	@echo "$(GREEN)Planning scp...$(NC)"
	cd scp && $(TF) plan -var-file=$(TF_VARS)

scp-apply:
	@echo "$(GREEN)Applying scp...$(NC)"
	cd scp && $(TF) apply -var-file=$(TF_VARS) -auto-approve

scp-destroy:
	@echo "$(RED)Destroying scp...$(NC)"
	cd scp && $(TF) destroy -var-file=$(TF_VARS) -auto-approve

scp-validate:
	cd scp && $(TF) validate

scp-fmt:
	cd scp && $(TF) fmt -recursive -check

# IAM
iam-init:
	@echo "$(GREEN)Initializing iam...$(NC)"
	cd iam && $(TF) init

iam-plan:
	@echo "$(GREEN)Planning iam...$(NC)"
	cd iam && $(TF) plan -var-file=$(TF_VARS)

iam-apply:
	@echo "$(GREEN)Applying iam...$(NC)"
	cd iam && $(TF) apply -var-file=$(TF_VARS) -auto-approve

iam-destroy:
	@echo "$(RED)Destroying iam...$(NC)"
	cd iam && $(TF) destroy -var-file=$(TF_VARS) -auto-approve

iam-validate:
	cd iam && $(TF) validate

iam-fmt:
	cd iam && $(TF) fmt -recursive -check

# Security
security-init:
	@echo "$(GREEN)Initializing security...$(NC)"
	cd security && $(TF) init

security-plan:
	@echo "$(GREEN)Planning security...$(NC)"
	cd security && $(TF) plan -var-file=$(TF_VARS)

security-apply:
	@echo "$(GREEN)Applying security...$(NC)"
	cd security && $(TF) apply -var-file=$(TF_VARS) -auto-approve

security-destroy:
	@echo "$(RED)Destroying security...$(NC)"
	cd security && $(TF) destroy -var-file=$(TF_VARS) -auto-approve

security-validate:
	cd security && $(TF) validate

security-fmt:
	cd security && $(TF) fmt -recursive -check

# Networking
networking-init:
	@echo "$(GREEN)Initializing networking...$(NC)"
	cd networking && $(TF) init

networking-plan:
	@echo "$(GREEN)Planning networking...$(NC)"
	cd networking && $(TF) plan -var-file=$(TF_VARS)

networking-apply:
	@echo "$(GREEN)Applying networking...$(NC)"
	cd networking && $(TF) apply -var-file=$(TF_VARS) -auto-approve

networking-destroy:
	@echo "$(RED)Destroying networking...$(NC)"
	cd networking && $(TF) destroy -var-file=$(TF_VARS) -auto-approve

networking-validate:
	cd networking && $(TF) validate

networking-fmt:
	cd networking && $(TF) fmt -recursive -check

# Data Protection
data-protection-init:
	@echo "$(GREEN)Initializing data-protection...$(NC)"
	cd data-protection && $(TF) init

data-protection-plan:
	@echo "$(GREEN)Planning data-protection...$(NC)"
	cd data-protection && $(TF) plan -var-file=$(TF_VARS)

data-protection-apply:
	@echo "$(GREEN)Applying data-protection...$(NC)"
	cd data-protection && $(TF) apply -var-file=$(TF_VARS) -auto-approve

data-protection-destroy:
	@echo "$(RED)Destroying data-protection...$(NC)"
	cd data-protection && $(TF) destroy -var-file=$(TF_VARS) -auto-approve

data-protection-validate:
	cd data-protection && $(TF) validate

data-protection-fmt:
	cd data-protection && $(TF) fmt -recursive -check

# Incident Response
incident-response-init:
	@echo "$(GREEN)Initializing incident-response...$(NC)"
	cd incident-response && $(TF) init

incident-response-plan:
	@echo "$(GREEN)Planning incident-response...$(NC)"
	cd incident-response && $(TF) plan -var-file=$(TF_VARS)

incident-response-apply:
	@echo "$(GREEN)Applying incident-response...$(NC)"
	cd incident-response && $(TF) apply -var-file=$(TF_VARS) -auto-approve

incident-response-destroy:
	@echo "$(RED)Destroying incident-response...$(NC)"
	cd incident-response && $(TF) destroy -var-file=$(TF_VARS) -auto-approve

incident-response-validate:
	cd incident-response && $(TF) validate

incident-response-fmt:
	cd incident-response && $(TF) fmt -recursive -check

# Backup
backup-init:
	@echo "$(GREEN)Initializing backup...$(NC)"
	cd backup && $(TF) init

backup-plan:
	@echo "$(GREEN)Planning backup...$(NC)"
	cd backup && $(TF) plan -var-file=$(TF_VARS)

backup-apply:
	@echo "$(GREEN)Applying backup...$(NC)"
	cd backup && $(TF) apply -var-file=$(TF_VARS) -auto-approve

backup-destroy:
	@echo "$(RED)Destroying backup...$(NC)"
	cd backup && $(TF) destroy -var-file=$(TF_VARS) -auto-approve

backup-validate:
	cd backup && $(TF) validate

backup-fmt:
	cd backup && $(TF) fmt -recursive -check