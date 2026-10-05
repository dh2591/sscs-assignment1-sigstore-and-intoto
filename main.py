import argparse
import requests
import json
import base64

from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    # TODO: verify that log index value is sane and valid
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("Log index must be a non-negative integer")

    # Rekor API address
    url = "https://rekor.sigstore.dev/api/v1/log/entries"

    # Tell Rekor which log entry we want
    params = {"logIndex": log_index}

    # Send the request to Rekor
    response = requests.get(url, params=params, timeout=30)

    # Stop if Rekor returned an HTTP error
    response.raise_for_status()

    # Convert Rekor's response into Python data
    data = response.json()

    if debug:
        print(json.dumps(data, indent=4))

    # Make sure Rekor actually returned an entry
    if not data:
        raise ValueError("No Rekor entry found")

    # Rekor returns the entry under a UUID key
    entry_uuid = next(iter(data))

    return data[entry_uuid]

def get_verification_proof(log_index, debug=False):
    # TODO: verify that log index value is sane and valid
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("Log index must be a non-negative integer")

    # Get the Rekor entry using the function we just created
    entry = get_log_entry(log_index, debug)

    # Get the verification information from the entry
    verification = entry.get("verification", {})

    # Get the inclusion proof
    inclusion_proof = verification.get("inclusionProof")

    # Make sure an inclusion proof was found
    if inclusion_proof is None:
        raise ValueError("No inclusion proof found in Rekor entry")

    # Print the proof if debug mode is turned on
    if debug:
        print("Inclusion proof:")
        print(json.dumps(inclusion_proof, indent=4))

    return inclusion_proof

def inclusion(log_index, artifact_filepath, debug=False):
    # TODO::
    # verify that log index and artifact filepath values are sane
    # extract_public_key(certificate)
    # verify_artifact_signature(signature, public_key, artifact_filepath)
    # get_verification_proof(log_index)
    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("Log index must be a non-negative integer")

    # Make sure an artifact filename was provided
    if not artifact_filepath:
        raise ValueError("Artifact filepath is required")

    # Get the entry from Rekor
    entry = get_log_entry(log_index, debug)

    # The body of the Rekor entry is Base64 encoded.
    # Decode it and convert the JSON into a Python dictionary.
    body = json.loads(
        base64.b64decode(entry["body"]).decode("utf-8")
    )

    # Get the Base64-encoded signature from the Rekor entry
    signature_b64 = body["spec"]["signature"]["content"]

    # Get the Base64-encoded certificate from the Rekor entry
    certificate_b64 = body["spec"]["signature"]["publicKey"]["content"]

    # Decode the signature and certificate
    signature = base64.b64decode(signature_b64)
    certificate = base64.b64decode(certificate_b64) 

    # Extract the public key from the certificate
    public_key = extract_public_key(certificate)

    # Verify that the signature belongs to our artifact
    verify_artifact_signature(
        signature,
        public_key,
        artifact_filepath
    )

    # Get the inclusion proof from Rekor
    inclusion_proof = get_verification_proof(log_index, debug)

    # Get the values needed to verify the Merkle proof
    index = inclusion_proof["logIndex"]
    tree_size = inclusion_proof["treeSize"]
    hashes = inclusion_proof["hashes"]
    root_hash = inclusion_proof["rootHash"]

    # Calculate the leaf hash for this Rekor entry
    leaf_hash = compute_leaf_hash(entry["body"])

    # Verify that our entry is included in the Rekor Merkle tree
    verify_inclusion(
        DefaultHasher,
        index,
        tree_size,
        leaf_hash,
        hashes,
        root_hash,
        debug
    )

    print("Offline verification successful")

def get_latest_checkpoint(debug=False):
    # TODO: Fetch the latest checkpoint from rekor
    # Rekor API endpoint for the current log information
    url = "https://rekor.sigstore.dev/api/v1/log"

    # Request the latest log information from Rekor
    response = requests.get(url, timeout=30)

    # Stop if the request was unsuccessful
    response.raise_for_status()

    # Convert the JSON response into a Python dictionary
    data = response.json()

    # Store the checkpoint information we need
    checkpoint = {
        "treeID": data["treeID"],
        "treeSize": data["treeSize"],
        "rootHash": data["rootHash"]
    }

    # If debug mode is enabled, save the checkpoint to a file
    if debug:
        with open("checkpoint.json", "w") as checkpoint_file:
            json.dump(checkpoint, checkpoint_file, indent=4)

    return checkpoint

def consistency(prev_checkpoint, debug=False):
    # TODO: 
    # verify that prev checkpoint is not empty
    # get_latest_checkpoint()
    
    # Make sure an older checkpoint was provided
    if not prev_checkpoint:
        raise ValueError("Previous checkpoint is required")

    # Get the latest checkpoint from Rekor
    latest_checkpoint = get_latest_checkpoint(debug)

    # Make sure both checkpoints belong to the same Rekor tree
    if str(prev_checkpoint["treeID"]) != str(latest_checkpoint["treeID"]):
        raise ValueError("Tree IDs do not match")

    # Get the old and new tree sizes
    old_size = prev_checkpoint["treeSize"]
    new_size = latest_checkpoint["treeSize"]

    # The older checkpoint must actually be older
    if old_size >= new_size:
        raise ValueError("Previous checkpoint must have a smaller tree size")

    # Ask Rekor for a consistency proof between the two tree sizes
    url = "https://rekor.sigstore.dev/api/v1/log/proof"
    params = {
        "firstSize": old_size,
        "lastSize": new_size,
        "treeID": prev_checkpoint["treeID"]
    }

    response = requests.get(url, params=params, timeout=30)
    response.raise_for_status()

    proof_data = response.json()

    if debug:
        print("Consistency proof:")
        print(json.dumps(proof_data, indent=4))

    # Verify that the old tree is consistent with the latest tree
    verify_consistency(
        DefaultHasher,
        old_size,
        new_size,
        proof_data["hashes"],
        prev_checkpoint["rootHash"],
        latest_checkpoint["rootHash"]
    )

    print("Consistency verification successful")

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
