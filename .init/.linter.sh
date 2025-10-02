#!/bin/bash
cd /home/kavia/workspace/code-generation/jira-confluence-connector-146762-146772/integration_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

