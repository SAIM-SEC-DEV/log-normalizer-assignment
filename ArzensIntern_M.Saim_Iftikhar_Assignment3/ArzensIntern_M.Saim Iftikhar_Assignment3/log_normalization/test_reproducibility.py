import subprocess
import sys
import os
import hashlib
import filecmp

def sha256_file(filepath):
    sha = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha.update(chunk)
    return sha.hexdigest()

def test_reproducibility():
    # Run first time
    subprocess.run([sys.executable, 'normalizer.py', '--input', 'sample_mixed_logs.txt',
                    '--output-csv', 'run1.csv', '--output-json', 'run1.json'], check=True)
    # Run second time
    subprocess.run([sys.executable, 'normalizer.py', '--input', 'sample_mixed_logs.txt',
                    '--output-csv', 'run2.csv', '--output-json', 'run2.json'], check=True)
    # Compare
    csv_match = filecmp.cmp('run1.csv', 'run2.csv', shallow=False)
    json_match = filecmp.cmp('run1.json', 'run2.json', shallow=False)
    if csv_match and json_match:
        print("PASS: Both runs produced identical outputs.")
        # Optionally verify checksums
        print(f"CSV SHA256: {sha256_file('run1.csv')}")
        print(f"JSON SHA256: {sha256_file('run1.json')}")
    else:
        print("FAIL: Outputs differ.")
        sys.exit(1)

if __name__ == '__main__':
    test_reproducibility()