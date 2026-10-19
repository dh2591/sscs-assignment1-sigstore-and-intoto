import base64
import json
from unittest.mock import Mock, patch

import pytest

from main import (
    get_log_entry,
    get_verification_proof,
    get_latest_checkpoint,
    consistency,
)


def test_get_log_entry_invalid_index():
    # A negative log index should not be accepted.
    with pytest.raises(ValueError):
        get_log_entry(-1)


def test_get_log_entry_success():
    # Simulate a successful response from Rekor.
    fake_entry = {"body": "example"}

    with patch("main.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {"fake-uuid": fake_entry}
        mock_get.return_value = mock_response

        result = get_log_entry(123)

        assert result == fake_entry
        mock_response.raise_for_status.assert_called_once()


def test_get_log_entry_empty_response():
    # Rekor returning no entries should raise an error.
    with patch("main.requests.get") as mock_get:
        mock_get.return_value.json.return_value = {}

        with pytest.raises(ValueError, match="No Rekor entry found"):
            get_log_entry(123)


def test_get_verification_proof_success():
    # Check that the inclusion proof is extracted correctly.
    fake_proof = {"logIndex": 123, "hashes": []}
    fake_entry = {"verification": {"inclusionProof": fake_proof}}

    with patch("main.get_log_entry", return_value=fake_entry):
        result = get_verification_proof(123)

        assert result == fake_proof


def test_get_verification_proof_missing():
    # An entry without an inclusion proof should raise an error.
    with patch("main.get_log_entry", return_value={}):
        with pytest.raises(ValueError, match="No inclusion proof"):
            get_verification_proof(123)


def test_get_latest_checkpoint():
    # Simulate Rekor returning checkpoint information.
    fake_checkpoint = {
        "treeID": "123",
        "treeSize": 100,
        "rootHash": "example-hash",
    }

    with patch("main.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = fake_checkpoint
        mock_get.return_value = mock_response

        result = get_latest_checkpoint()

        assert result == fake_checkpoint
        mock_response.raise_for_status.assert_called_once()


def test_consistency_missing_checkpoint():
    # A previous checkpoint must be provided.
    with pytest.raises(ValueError, match="Previous checkpoint"):
        consistency(None)


def test_consistency_different_tree_ids():
    # Checkpoints from different trees should not be compared.
    old_checkpoint = {
        "treeID": "111",
        "treeSize": 10,
        "rootHash": "old-hash",
    }

    new_checkpoint = {
        "treeID": "222",
        "treeSize": 20,
        "rootHash": "new-hash",
    }

    with patch("main.get_latest_checkpoint", return_value=new_checkpoint):
        with pytest.raises(ValueError, match="Tree IDs do not match"):
            consistency(old_checkpoint)


def test_consistency_invalid_tree_size():
    # The previous checkpoint must have a smaller tree size.
    old_checkpoint = {
        "treeID": "111",
        "treeSize": 20,
        "rootHash": "old-hash",
    }

    new_checkpoint = {
        "treeID": "111",
        "treeSize": 10,
        "rootHash": "new-hash",
    }

    with patch("main.get_latest_checkpoint", return_value=new_checkpoint):
        with pytest.raises(ValueError, match="smaller tree size"):
            consistency(old_checkpoint)


def test_inclusion_success(tmp_path, capsys):
    # Create a temporary artifact file.
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("Hello World")

    # Create a fake Rekor entry.
    fake_body = {
        "spec": {
            "signature": {
                "content": base64.b64encode(b"fake-signature").decode(),
                "publicKey": {
                    "content": base64.b64encode(b"fake-certificate").decode()
                }
            }
        }
    }

    encoded_body = base64.b64encode(
        json.dumps(fake_body).encode()
    ).decode()

    fake_entry = {"body": encoded_body}

    fake_proof = {
        "logIndex": 123,
        "treeSize": 200,
        "hashes": [],
        "rootHash": "fake-root-hash"
    }

    # Simulate verification without contacting Rekor.
    with patch("main.get_log_entry", return_value=fake_entry), \
         patch("main.get_verification_proof", return_value=fake_proof), \
         patch("main.extract_public_key", return_value=b"fake-public-key"), \
         patch("main.verify_artifact_signature") as mock_signature, \
         patch("main.verify_inclusion") as mock_inclusion:

        from main import inclusion

        inclusion(123, str(artifact))

        assert mock_signature.called
        assert mock_inclusion.called

    assert "Offline verification successful" in capsys.readouterr().out


def test_inclusion_missing_artifact():
    # Reject an empty artifact filepath.
    from main import inclusion

    with pytest.raises(ValueError):
        inclusion(123, "")


def test_inclusion_nonexistent_file(tmp_path):
    # Reject a filepath that does not exist.
    from main import inclusion

    missing_file = tmp_path / "missing.txt"

    with pytest.raises(ValueError):
        inclusion(123, str(missing_file))


def test_inclusion_invalid_index():
    # Reject a negative log index.
    from main import inclusion

    with pytest.raises(ValueError):
        inclusion(-1, "artifact.txt")


def test_consistency_success(capsys):
    # Create an older checkpoint.
    old_checkpoint = {
        "treeID": "111",
        "treeSize": 10,
        "rootHash": "old-root"
    }

    # Create a newer checkpoint from the same tree.
    new_checkpoint = {
        "treeID": "111",
        "treeSize": 20,
        "rootHash": "new-root"
    }

    # Simulate the consistency proof returned by Rekor.
    fake_proof = {
        "hashes": ["fake-hash"]
    }

    with patch("main.get_latest_checkpoint", return_value=new_checkpoint), \
         patch("main.requests.get") as mock_get, \
         patch("main.verify_consistency") as mock_verify:

        mock_response = Mock()
        mock_response.json.return_value = fake_proof
        mock_get.return_value = mock_response

        consistency(old_checkpoint)

        # Make sure the verification function was called.
        mock_verify.assert_called_once()

    # Check that the success message was printed.
    assert "Consistency verification successful" in capsys.readouterr().out
