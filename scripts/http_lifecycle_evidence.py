"""Validate actual lifecycle outcomes and independently expected consent denials."""
import re

REQUIRED_OPERATIONS = {'plan', 'apply', 'status', 'doctor', 'repair', 'destroy'}


def validate_http_observations(rows):
    if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError('HTTP lifecycle observations are invalid')
    if {row.get('operation') for row in rows} != REQUIRED_OPERATIONS:
        raise ValueError('complete HTTP operation set not observed')
    for index, row in enumerate(rows):
        if row.get('state') == 'succeeded':
            continue
        if not (row.get('operation') in {'apply', 'repair', 'destroy'}
                and row.get('state') == 'failed' and row.get('expected_refusal') is True
                and row.get('code') == 'approval_required'
                and row.get('cause') == 'impact-confirmation-required'
                and isinstance(row.get('plan_id'), str)
                and re.fullmatch('[0-9a-f]{64}', row['plan_id'])):
            raise ValueError('unexpected native failure cannot become PASS')
        if not any(later.get('operation') == row['operation'] and later.get('state') == 'succeeded'
                   for later in rows[index + 1:]):
            raise ValueError('expected consent refusal lacks a later verified execution')
