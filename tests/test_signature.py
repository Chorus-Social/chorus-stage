from chorus_stage.core.security import verify_signature

def test_verify_signature_rejects_bad_inputs():
    assert verify_signature("zz", b"msg", "aa") is False
