import unittest
from http_lifecycle_evidence import validate_http_observations


class HTTPReceiptTests(unittest.TestCase):
    def setUp(self):
        self.success = [{'operation': name, 'state': 'succeeded'} for name in ['plan', 'apply', 'status', 'doctor', 'repair', 'destroy']]
        self.denial = {'operation': 'apply', 'state': 'failed', 'expected_refusal': True,
                       'code': 'approval_required', 'cause': 'impact-confirmation-required', 'plan_id': 'a' * 64}

    def test_expected_denial_requires_later_actual_success(self):
        validate_http_observations([self.denial, *self.success])
        with self.assertRaises(ValueError):
            validate_http_observations([*self.success, self.denial])

    def test_partial_cancelled_stale_or_ownership_failure_never_passes(self):
        for change in [{'state': 'cancelled'}, {'cause': 'stale-impact-consent'},
                       {'code': 'ownership_ambiguous'}, {'expected_refusal': False}, {'plan_id': 'guessed'}]:
            with self.assertRaises(ValueError):
                validate_http_observations([{**self.denial, **change}, *self.success])

    def test_missing_actual_operations_or_malformed_evidence_fails(self):
        for rows in [self.success[:-1], None, [], [None]]:
            with self.assertRaises(ValueError):
                validate_http_observations(rows)

    def test_read_only_failure_cannot_be_reclassified_as_provider_consent(self):
        with self.assertRaises(ValueError):
            validate_http_observations([{**self.denial, 'operation': 'status'}, *self.success])


if __name__ == '__main__':
    unittest.main()
