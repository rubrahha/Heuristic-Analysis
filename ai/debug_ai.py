import os
from bridge import _extract_and_score_worker

print("Testing EMBER AI Pipeline...")

# Let's test it on a standard Windows file that we know exists
test_file = r"C:\Windows\System32\calc.exe"

print(f"Scanning: {test_file}")
result = _extract_and_score_worker(test_file, 0)

print("\n=== AI SCAN RESULT ===")
print(f"File: {result[0]}")
print(f"AI Score: {result[1]}")
print("Indicators:")
for ind in result[2]:
    print(f"  - {ind}")
print("======================\n")