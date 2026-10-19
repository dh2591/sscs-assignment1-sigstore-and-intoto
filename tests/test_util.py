from unittest.mock import Mock, patch

import pytest
from cryptography.exceptions import InvalidSignature

from util import extract_public_key, verify_artifact_signature


def test_extract_public_key():
    # Simulate extracting a public key from a certificate.
    fake_public_key = Mock()
    fake_public_key.public_bytes.return_value = b"fake-public-key"

    fake_certificate = Mock()
    fake_certificate.public_key.return_value = fake_public_key

    with patch(
        "util.x509.load_pem_x509_certificate",
        return_value=fake_certificate
    ):
        result = extract_public_key(b"fake-certificate")

    assert result == b"fake-public-key"


def test_extract_public_key_invalid_certificate():
    # An invalid certificate should raise ValueError.
    with pytest.raises(ValueError):
        extract_public_key(b"not-a-valid-certificate")


def test_verify_artifact_signature_success(tmp_path):
    # Simulate a valid digital signature.
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("Hello World")

    fake_public_key = Mock()

    with patch(
        "util.load_pem_public_key",
        return_value=fake_public_key
    ):
        verify_artifact_signature(
            b"fake-signature",
            b"fake-public-key",
            str(artifact)
        )

    fake_public_key.verify.assert_called_once()



def test_verify_artifact_signature_invalid(tmp_path):
    # Create a temporary artifact file.
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("Hello World")

    # Simulate an invalid digital signature.
    fake_public_key = Mock()
    fake_public_key.verify.side_effect = InvalidSignature()

    with patch(
        "util.load_pem_public_key",
        return_value=fake_public_key
    ):
        # An invalid signature should stop verification.
        with pytest.raises(ValueError, match="Signature is invalid"):
            verify_artifact_signature(
                b"fake-signature",
                b"fake-public-key",
                str(artifact)
            )



def test_verify_artifact_signature_error(tmp_path, capsys):
    # Simulate an unexpected verification error.
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("Hello World")

    fake_public_key = Mock()
    fake_public_key.verify.side_effect = RuntimeError("Test error")

    with patch(
        "util.load_pem_public_key",
        return_value=fake_public_key
    ):
        verify_artifact_signature(
            b"fake-signature",
            b"fake-public-key",
            str(artifact)
        )

    output = capsys.readouterr().out
    assert "Exception in verifying artifact signature" in output
