.PHONY: check
check:
	black cryptopals tests
	mypy cryptopals
	pytest