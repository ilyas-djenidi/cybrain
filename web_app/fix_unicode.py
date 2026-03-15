import glob
import os

files_to_fix = glob.glob(r"c:\Users\HP\Desktop\misconfiguration_datasets-master\web_app\*.py")

# Character-specific replacements
replacements = {
    '═': '=',
    '—': '-',
    '–': '-',  # en-dash
    '─': '-',  # horizontal bar
    '≤': '<=',
    '…': '...',
    '⚠️': '[!]',
    '•': '*',
    '→': '->',
    '×': 'x',
    '✔': '[OK]',
    '✖': '[FAIL]',
    '⚡': '[!]',
    '🔍': '[?]',
    '📡': '[>]',
    '🔴': '[CRITICAL]',
    '🟠': '[HIGH]',
    '🟡': '[MEDIUM]',
    '🟢': '[LOW]',
    'ℹ️': '[INFO]',
    '•': '*'
}

for file_path in files_to_fix:
    if os.path.basename(file_path) == "fix_unicode.py":
        continue
        
    print(f"Sanitizing {file_path}...")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        new_content = ""
        for char in content:
            if ord(char) > 127:
                if char in replacements:
                    new_content += replacements[char]
                else:
                    new_content += "?"
            else:
                new_content += char
                
        if content != new_content:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(new_content)
    except Exception as e:
        print(f"Error processing {file_path}: {e}")

print("All Python files are now strictly ASCII/CP1252-safe!")
