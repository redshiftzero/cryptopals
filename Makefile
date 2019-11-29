.PHONY: check
check:
	black cryptopals tests
	flake8 --exclude=.venv --max-line-length=88 --ignore=E203,W503
	mypy --ignore-missing-imports cryptopals
	pytest
