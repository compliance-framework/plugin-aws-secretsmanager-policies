OPA := $(shell command -v opa 2> /dev/null)
ifndef OPA
$(error opa CLI not found. Install from https://www.openpolicyagent.org/docs/latest/#running-opa)
endif

.PHONY: test validate clean build

test:        ## Run policy unit tests
	@$(OPA) test policies

validate:    ## Lint/parse policies
	@$(OPA) check --strict policies

clean:
	@rm -f dist/*

build: clean ## Build the OCI bundle
	@mkdir -p dist/
	@$(OPA) build -b policies -o dist/bundle.tar.gz
