# Cryptopals

This repo has my Python solutions to cryptopals, my Golang solutions are in: https://github.com/redshiftzero/gocryptopals

## Setup

```
virtualenv --python=python3 .venv
source .venv/bin/activate
pip install -r dev-requirements.txt
```

## Run tests

```
pytest
```

## Run type checker

```
mypy cryptopals
```