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

# Additional tests for the Merkle proof functions

def test_hasher_size():
    # SHA-256 produces a 32-byte hash.
    from merkle_proof import DefaultHasher

    assert DefaultHasher.size() == 32


def test_empty_root():
    # The empty root should be the SHA-256 hash of empty data.
    from merkle_proof import DefaultHasher

    expected = hashlib.sha256(b"").digest()
    assert DefaultHasher.empty_root() == expected


def test_hash_leaf():
    # A leaf hash starts with a 0 byte, followed by the data.
    from merkle_proof import DefaultHasher

    expected = hashlib.sha256(b"\x00hello").digest()
    assert DefaultHasher.hash_leaf(b"hello") == expected


def test_hash_children():
    # A parent hash starts with a 1 byte and combines two hashes.
    from merkle_proof import DefaultHasher

    left = DefaultHasher.hash_leaf(b"left")
    right = DefaultHasher.hash_leaf(b"right")

    expected = hashlib.sha256(b"\x01" + left + right).digest()
    assert DefaultHasher.hash_children(left, right) == expected


def test_verify_match_success():
    # Matching hashes should not raise an exception.
    from merkle_proof import verify_match

    verify_match(b"same", b"same")


def test_verify_match_failure():
    # Different hashes should raise RootMismatchError.
    from merkle_proof import RootMismatchError, verify_match

    with pytest.raises(RootMismatchError):
        verify_match(b"first", b"second")


def test_inner_proof_size():
    # Check the expected inner proof size.
    from merkle_proof import inner_proof_size

    assert inner_proof_size(0, 1) == 0
    assert inner_proof_size(0, 2) == 1


def test_root_from_inclusion_proof():
    # A tree containing one leaf has that leaf's hash as its root.
    from merkle_proof import DefaultHasher, root_from_inclusion_proof

    leaf_hash = DefaultHasher.hash_leaf(b"hello")

    result = root_from_inclusion_proof(
        DefaultHasher, 0, 1, leaf_hash, []
    )

    assert result == leaf_hash


def test_invalid_inclusion_index():
    # An index outside the tree should raise ValueError.
    from merkle_proof import DefaultHasher, root_from_inclusion_proof

    leaf_hash = DefaultHasher.hash_leaf(b"hello")

    with pytest.raises(ValueError):
        root_from_inclusion_proof(
            DefaultHasher, 2, 1, leaf_hash, []
        )


def test_verify_consistency_same_tree():
    # Identical tree sizes and root hashes are consistent.
    from merkle_proof import DefaultHasher, verify_consistency

    root = DefaultHasher.hash_leaf(b"hello").hex()

    verify_consistency(DefaultHasher, 1, 1, [], root, root)


def test_verify_consistency_different_roots():
    # Identical tree sizes must have matching root hashes.
    from merkle_proof import (
        DefaultHasher,
        RootMismatchError,
        verify_consistency,
    )

    root1 = DefaultHasher.hash_leaf(b"hello").hex()
    root2 = DefaultHasher.hash_leaf(b"world").hex()

    with pytest.raises(RootMismatchError):
        verify_consistency(DefaultHasher, 1, 1, [], root1, root2)


def test_verify_consistency_invalid_tree_size():
    # The newer tree cannot be smaller than the older tree.
    from merkle_proof import DefaultHasher, verify_consistency

    root = DefaultHasher.hash_leaf(b"hello").hex()

    with pytest.raises(ValueError):
        verify_consistency(DefaultHasher, 5, 3, [], root, root)


def test_verify_consistency_empty_tree():
    # An empty tree can grow into a nonempty tree.
    from merkle_proof import DefaultHasher, verify_consistency

    empty_root = DefaultHasher.empty_root().hex()
    new_root = DefaultHasher.hash_leaf(b"hello").hex()

    verify_consistency(DefaultHasher, 0, 1, [], empty_root, new_root)


def test_verify_inclusion_single_leaf():
    # A single-leaf tree needs no additional proof hashes.
    from merkle_proof import DefaultHasher, verify_inclusion

    leaf_hash = DefaultHasher.hash_leaf(b"hello").hex()

    verify_inclusion(
        DefaultHasher,
        0,
        1,
        leaf_hash,
        [],
        leaf_hash
    )


def test_chain_inner_left():
    # Combine a leaf hash with a sibling on its right.
    from merkle_proof import DefaultHasher, chain_inner

    leaf = DefaultHasher.hash_leaf(b"left")
    sibling = DefaultHasher.hash_leaf(b"right")

    expected = DefaultHasher.hash_children(leaf, sibling)

    assert chain_inner(DefaultHasher, leaf, [sibling], 0) == expected


def test_chain_inner_right():
    # Combine a sibling on the left with our leaf on the right.
    from merkle_proof import DefaultHasher, chain_inner

    sibling = DefaultHasher.hash_leaf(b"left")
    leaf = DefaultHasher.hash_leaf(b"right")

    expected = DefaultHasher.hash_children(sibling, leaf)

    assert chain_inner(DefaultHasher, leaf, [sibling], 1) == expected


def test_chain_inner_right_only():
    # Verify a right-side hash in the inner proof.
    from merkle_proof import DefaultHasher, chain_inner_right

    sibling = DefaultHasher.hash_leaf(b"left")
    leaf = DefaultHasher.hash_leaf(b"right")

    expected = DefaultHasher.hash_children(sibling, leaf)

    assert chain_inner_right(DefaultHasher, leaf, [sibling], 1) == expected



def test_chain_border_right():
    # Combine a hash with another hash along the tree border.
    from merkle_proof import DefaultHasher, chain_border_right

    left = DefaultHasher.hash_leaf(b"left")
    right = DefaultHasher.hash_leaf(b"right")

    # The function places the proof hash on the left.
    expected = DefaultHasher.hash_children(left, right)

    assert chain_border_right(DefaultHasher, right, [left]) == expected



def test_invalid_leaf_hash_size():
    # Reject leaf hashes that are not the correct length.
    from merkle_proof import DefaultHasher, root_from_inclusion_proof

    with pytest.raises(ValueError, match="unexpected size"):
        root_from_inclusion_proof(
            DefaultHasher,
            0,
            1,
            b"too-short",
            []
        )


def test_verify_inclusion_debug(capsys):
    # Check that debug mode prints the calculated and expected root hashes.
    from merkle_proof import DefaultHasher, verify_inclusion

    leaf_hash = DefaultHasher.hash_leaf(b"hello").hex()

    verify_inclusion(
        DefaultHasher,
        0,
        1,
        leaf_hash,
        [],
        leaf_hash,
        debug=True
    )

    output = capsys.readouterr().out

    assert "Calculated root hash" in output
    assert "Given root hash" in output
