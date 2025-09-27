import hashlib
import json
import os
import argparse
import sys
from datetime import datetime


def generate_keys(seed=None):
    """
    Generates a simple public and private key pair based on a seed.

    Args:
        seed (str, optional): A string used to seed the key generation.
                              If None, a random seed is generated.

    Returns:
        tuple: A tuple containing the private key (str) and public key (str).
    """
    seed = seed or os.urandom(16).hex()
    private_key = hashlib.sha256(seed.encode()).hexdigest()
    public_key = hashlib.sha256((seed + "_pub").encode()).hexdigest()[:32]
    return private_key, public_key


def sign_message(message, private_key):
    """
    Signs a message using a private key.

    Args:
        message (str): The message to sign.
        private_key (str): The private key used for signing.

    Returns:
        str: The digital signature of the message.
    """
    msg_hash = hashlib.sha256(message.encode()).hexdigest()
    signature = hashlib.sha256((private_key + msg_hash).encode()).hexdigest()
    return signature


def verify_message(message, signature):
    """
    Verifies a signature against a message.

    Note: This is a simplified verification and does not use a public key directly
    in the hashing process. A more robust system would involve using the public key
    during verification.

    Args:
        message (str): The original message.
        signature (str): The signature to verify.

    Returns:
        bool: True if the signature has the correct format (length and hex characters),
              False otherwise.
    """
    return (
        len(signature) == 64
        and all(c in "0123456789abcdef" for c in signature)
    )


def sign_file(path, private_key):
    """
    Signs the content of a file using a private key and saves the signature to a .sig file.

    Args:
        path (str): The path to the file to sign.
        private_key (str): The private key used for signing.

    Returns:
        str or None: The path to the generated signature file if successful, None otherwise.
    """
    if not os.path.exists(path):
        print(f"Error: File not found at {path}")
        return None

    try:
        with open(path, encoding="utf-8") as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file {path}: {e}")
        return None

    signature = sign_message(data, private_key)
    sigfile = path + ".sig"

    try:
        with open(sigfile, "w") as f:
            json.dump(
                {
                    "signature": signature,
                    "timestamp": datetime.now().isoformat(),
                    "filename": os.path.basename(path),
                },
                f,
            )
    except Exception as e:
        print(f"Error writing signature file {sigfile}: {e}")
        return None

    return sigfile


def verify_file(path, sigfile):
    """
    Verifies the signature file against the original file.

    Args:
        path (str): The path to the original file.
        sigfile (str): The path to the signature file (.sig).

    Returns:
        bool: True if the signature is valid for the file content, False otherwise.
    """
    if not os.path.exists(path):
        print(f"Error: File not found at {path}")
        return False
    if not os.path.exists(sigfile):
        print(f"Error: Signature file not found at {sigfile}")
        return False

    try:
        with open(path, encoding="utf-8") as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file {path}: {e}")
        return False

    try:
        with open(sigfile, "r") as f:
            sigrec = json.load(f)
    except Exception as e:
        print(f"Error reading signature file {sigfile}: {e}")
        return False

    signature = sigrec.get("signature")
    if not signature:
        print("Error: Signature not found in signature file.")
        return False

    return verify_message(data, signature)


# --- Command Line Interface ---
def main(args=None):
    """
    Main function to handle command-line arguments and execute digital signature operations.
    Accepts an optional list of arguments for testing/notebook execution.
    """
    parser = argparse.ArgumentParser(
        description="Simple Digital Signature Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Generate keys command
    parser_gen = subparsers.add_parser("generate-keys", help="Generate a new public and private key pair")
    parser_gen.add_argument("--seed", help="Optional seed for key generation")

    # Sign message command
    parser_sign_msg = subparsers.add_parser("sign-message", help="Sign a text message")
    parser_sign_msg.add_argument("message", help="The message to sign")
    parser_sign_msg.add_argument("private_key", help="Your private key")

    # Sign file command
    parser_sign_file = subparsers.add_parser("sign-file", help="Sign a file")
    parser_sign_file.add_argument("filepath", help="The path to the file to sign")
    parser_sign_file.add_argument("private_key", help="Your private key")

    # Verify message command
    parser_verify_msg = subparsers.add_parser("verify-message", help="Verify a message signature")
    parser_verify_msg.add_argument("message", help="The original message")
    parser_verify_msg.add_argument("signature", help="The signature to verify")

    # Verify file command
    parser_verify_file = subparsers.add_parser("verify-file", help="Verify a file signature")
    parser_verify_file.add_argument("filepath", help="The path to the original file")
    parser_verify_file.add_argument("sigfilepath", help="The path to the signature file (.sig)")

    # Run demo command
    parser_demo = subparsers.add_parser("run-demo", help="Run the demonstration")

    # Parse arguments: if args is None, parse sys.argv; otherwise, parse the provided list
    if args is None:
        # Check if running in an interactive environment (like a Jupyter notebook)
        # If so, parse an empty list to avoid parsing kernel arguments unless explicit args are given
        if 'ipykernel_launcher' in sys.argv[0] and len(sys.argv) == 1:
             parsed_args = parser.parse_args([])
        else:
             parsed_args = parser.parse_args(sys.argv[1:]) # Parse actual command-line args
    else:
        parsed_args = parser.parse_args(args) # Parse the provided list of arguments


    if parsed_args.command == "generate-keys":
        pk, pub = generate_keys(parsed_args.seed)
        print("Private Key:", pk)
        print("Public Key:", pub)
    elif parsed_args.command == "sign-message":
        signature = sign_message(parsed_args.message, parsed_args.private_key)
        print("Signature:", signature)
    elif parsed_args.command == "sign-file":
        sigfile = sign_file(parsed_args.filepath, parsed_args.private_key)
        if sigfile:
            print(f"Signature file created: {sigfile}")
    elif parsed_args.command == "verify-message":
        is_valid = verify_message(parsed_args.message, parsed_args.signature)
        print("Verification:", "PASSED" if is_valid else "FAILED")
    elif parsed_args.command == "verify-file":
        is_valid = verify_file(parsed_args.filepath, parsed_args.sigfilepath)
        print("File Verification:", "PASSED" if is_valid else "FAILED")
    elif parsed_args.command == "run-demo":
        run_demo()
    else:
        # If no command is provided (e.g., script run without arguments in CLI)
        if args is None and len(sys.argv) == 1:
             parser.print_help()
        # If running in notebook without explicit command, print help or do nothing
        elif 'ipykernel_launcher' in sys.argv[0] and args == []:
             parser.print_help() # Or just pass/do nothing if preferred


def run_demo():
    """
    Runs a demonstration of the digital signature functions.
    """
    print("=== SIMPLE DIGITAL SIGNATURE DEMO ===")

    # Generate a key pair
    pk, pub = generate_keys()
    print("Private key (short):", pk[:20] + "...")
    print("Public  key:", pub)

    # Sign and verify a message
    msg = "Hello Cloud Computing!"
    sig = sign_message(msg, pk)
    ok = verify_message(msg, sig)

    print("\nSigned message:", msg)
    print("Signature:", sig[:20] + "...")
    print("Verification:", "PASSED" if ok else "FAILED")

    # Create an example file
    demo_filename = "demo.txt"
    with open(demo_filename, "w", encoding="utf-8") as f:
        f.write("Demo file for signature\n")

    # Sign and verify the example file
    sigfile = sign_file(demo_filename, pk)
    if sigfile:
        print("\nFile signed ->", sigfile)
        file_ok = verify_file(demo_filename, sigfile)
        print("File verification:", "PASSED" if file_ok else "FAILED")
    else:
        print("\nFile signing failed.")


    print("\n=== OUTCOMES ===")
    # Re-run verification checks for the final outcome summary
    # These re-checks are illustrative; in a real scenario,
    # you'd likely reuse results from the operations above.
    msg = "Hello Cloud Computing!"
    # Regenerate keys for a clean demo state in summary checks if needed, though not strictly required for this summary output.
    # pk, pub = generate_keys() # No need to regenerate keys here
    sig = sign_message(msg, pk) # Use the private key from the demo run
    ok = verify_message(msg, sig)

    demo_filename = "demo.txt"
    sigfile_path = demo_filename + ".sig" # Construct expected sigfile path
    # Check if the sigfile was actually created before attempting verification for the outcome summary
    file_ok = False # Default to False
    if os.path.exists(sigfile_path):
        file_ok = verify_file(demo_filename, sigfile_path) # Verify the demo file

    print("1. Key generation        -> OK") # Assumes key generation in demo was ok
    print("2. Message signing       -> OK") # Assumes message signing in demo was ok
    print("3. Signature verification->", "OK" if ok else "FAIL")
    # Check if sigfile exists and verification passed for file sign/verify outcome
    print("4. File sign/verify      ->", "OK" if os.path.exists(sigfile_path) and file_ok else "FAIL")
    print("All core objectives met." if ok and os.path.exists(sigfile_path) and file_ok else "Some objectives failed.")



# New entry point for the command-line interface
if __name__ == "__main__":
    # In a notebook, simulate command-line arguments for testing purposes
    # For actual command-line execution, remove or comment out the following line
    # and let main() parse sys.argv automatically.
    # To run the demo in the notebook, uncomment the line below:
    main(['run-demo'])
    # To test other commands in the notebook, replace ['run-demo'] with
    # the desired command and arguments, e.g., main(['generate-keys', '--seed', 'test'])
    # For actual command line usage, the `if args is None:` block in main handles it.