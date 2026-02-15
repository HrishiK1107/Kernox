from app.services.endpoint_registry import endpoint_registry


def test_register_and_check():
    endpoint_registry.register("node-test", "host-test", "secret1234567890")
    assert endpoint_registry.is_registered("node-test") is True


def test_unregistered_returns_false():
    assert endpoint_registry.is_registered("nonexistent") is False
