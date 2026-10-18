# Import pytest and the function we want to test
import base64
import hashlib

import pytest

from merkle_proof import compute_leaf_hash, decomp_incl_proof


# Test the function with different valid inputs
@pytest.mark.parametrize(
    "index, size, expected",
    [
        (0, 1, (0, 0)),  # Tree with one leaf
        (3, 8, (3, 0)),  # Previously tested example
    ],
)
def test_decomp_incl_proof(index, size, expected):
    # Check that the function returns the expected result
    assert decomp_incl_proof(index, size) == expected


# Test that the leaf hash is calculated correctly
def test_compute_leaf_hash():
    # Create sample data
    data = b"hello"

    # Encode the data in Base64, as the function expects
    encoded_data = base64.b64encode(data).decode("utf-8")

    # Calculate the expected hash using the RFC 6962 leaf prefix
    expected_hash = hashlib.sha256(b"\x00" + data).hexdigest()

    # Compare the function's result with our expected hash
    actual_hash = compute_leaf_hash(encoded_data)

    assert actual_hash == expected_hash
