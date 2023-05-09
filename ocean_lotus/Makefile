#
# See `make help` for a list of all available commands.
#

include make/*.mk

ROOTDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: help
help: ## Show Makefile help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' | \
		sort
