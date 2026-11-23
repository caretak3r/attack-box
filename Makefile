COMMIT ?= HEAD
export COMMIT PLATFORM APPROVE

.PHONY: check release-check deploy
check release-check deploy:
	bash scripts/local-ci.sh $@
