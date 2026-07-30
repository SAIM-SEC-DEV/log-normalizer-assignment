import hashlib
import argparse
import os
from datetime import datetime

def sha256_file(filepath):
    sha = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha.update(chunk)
    return sha.hexdigest()

def md5_file(filepath):
    md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5.update(chunk)
    return md5.hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify', action='store_true', help='Verify checksums from file')
    args = parser.parse_args()

    files = ['sample_mixed_logs.txt', 'sample_clean.csv', 'sample_clean.json']
    if args.verify:
        with open('checksums.txt', 'r') as f:
            lines = f.readlines()
        ok = True
        for line in lines:
            fname, alg, expected = line.strip().split(':')
            if not os.path.exists(fname):
                print(f"FAIL: {fname} missing")
                ok = False
                continue
            if alg == 'SHA256':
                actual = sha256_file(fname)
            elif alg == 'MD5':
                actual = md5_file(fname)
            else:
                continue
            if actual == expected:
                print(f"OK: {fname} ({alg})")
            else:
                print(f"FAIL: {fname} ({alg}) expected {expected} got {actual}")
                ok = False
        if ok:
            print("Verification PASSED")
        else:
            print("Verification FAILED")
    else:
        # Generate checksums
        with open('checksums.txt', 'w') as out:
            out.write(f"Generated: {datetime.utcnow().isoformat()}Z\n")
            for fname in files:
                if os.path.exists(fname):
                    out.write(f"{fname}:SHA256:{sha256_file(fname)}\n")
                    out.write(f"{fname}:MD5:{md5_file(fname)}\n")
                else:
                    out.write(f"{fname}:SHA256:FILE_NOT_FOUND\n")
        print("Checksums written to checksums.txt")

if __name__ == '__main__':
    main()