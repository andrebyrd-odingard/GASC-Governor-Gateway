.PHONY: wasm test bench clean

OPA_BIN ?= bin/opa

# Build the WASM policy bundle from all .rego files in policies/
wasm:
	@mkdir -p build
	$(OPA_BIN) build -t wasm \
		-e 'gasc/governor/admission/result' \
		-e 'gasc/governor/integrity/allow_state_write' \
		-e 'gasc/governor/verification/allow_reintegration' \
		-o build/bundle.tar.gz \
		policies/
	@tar xzf build/bundle.tar.gz -C build policy.wasm
	@rm -f build/bundle.tar.gz
	@echo "Built build/policy.wasm ($(shell wc -c < build/policy.wasm) bytes)"

# Run full test suite with WASM bundle
test: wasm
	OPA_POLICY_BUNDLE=build/policy.wasm python -m pytest tests/ -q

# Run benchmark (slow tests) with WASM bundle
bench: wasm
	OPA_POLICY_BUNDLE=build/policy.wasm python -m pytest tests/ -q -m slow -s

clean:
	rm -rf build/
