import hashlib
import hmac
from typing import Dict


class EndpointRegistry:
    """
    In-memory trusted endpoint registry.
    Stores endpoint_id → hostname + hashed secret.
    """

    def __init__(self):
        self._endpoints: Dict[str, dict] = {}

    def _hash_secret(self, secret: str) -> str:
        return hashlib.sha256(secret.encode()).hexdigest()

    def register(self, endpoint_id: str, hostname: str, secret: str):
        hashed_secret = self._hash_secret(secret)

        self._endpoints[endpoint_id] = {
            "endpoint_id": endpoint_id,
            "hostname": hostname,
            "secret_hash": hashed_secret,
        }

    def is_registered(self, endpoint_id: str) -> bool:
        return endpoint_id in self._endpoints

    def verify_secret(self, endpoint_id: str, provided_secret: str) -> bool:
        endpoint = self._endpoints.get(endpoint_id)
        if not endpoint:
            return False

        expected_hash = endpoint["secret_hash"]
        provided_hash = self._hash_secret(provided_secret)

        return hmac.compare_digest(expected_hash, provided_hash)

    def get_secret_hash(self, endpoint_id: str) -> str | None:
        endpoint = self._endpoints.get(endpoint_id)
        return endpoint["secret_hash"] if endpoint else None


endpoint_registry = EndpointRegistry()
