.PHONY: check
check:
	black cryptopals tests
	mypy --ignore-missing-imports cryptopals
	pytest
