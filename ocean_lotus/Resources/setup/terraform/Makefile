TIMESTAMP := $(shell date -u +"%Y%m%d_%H%M%S")
GIT_HASH := $(shell git rev-parse --short HEAD)
DOCS_CFG = .terraform-docs.yml
TF_CODE_DIR = range

.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

fmt: ## Format Terraform code recursively
	terraform fmt --recursive .

docs: ## Update Terraform documentation
	$(info generating terraform-docs - requires terraform-docs to be installed...)
	terraform-docs -c $(DOCS_CFG) ./$(TF_CODE_DIR)
