name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    name: Python ${{ matrix.python-version }}
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.12"]

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip

      - name: Install package and test dependencies
        run: |
          python -m pip install --upgrade pip
          python -m pip install -e .
          python -m pip install -r requirements-dev.txt

      - name: Compile sources
        run: python -m compileall -q bioaegis

      - name: Run tests
        run: python -m pytest -q

      - name: CLI smoke tests
        run: |
          bioaegis --version
          bioaegis redteam
          bioaegis scan tests
          bioaegis audit tests
          bioaegis monitor tests --once
