from gravion_hacker.scope import AuthorizationRecord


def test_blank_targets_do_not_satisfy_scope():
    rec = AuthorizationRecord(scope_name="lab", owner="me", targets=["  ", ""], authorized=True)
    assert "at least one in-scope target is required" in rec.validate()


def test_valid_record_passes():
    rec = AuthorizationRecord(scope_name="lab", owner="me", targets=["example.com"], authorized=True)
    assert rec.validate() == []
