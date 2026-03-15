import re

with open('detect_apache_misconf.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    # Check if this line has an odd number of quotes (meaning it's unterminated)
    # Exclude comments
    clean_line = line.split('#')[0] if not line.strip().startswith('#') else ''
    
    if '\"' in clean_line and clean_line.count('\"') % 2 != 0:
        # String is unclosed, look ahead to the next line
        if i + 1 < len(lines):
            next_line = lines[i+1]
            if '\"' in next_line:
                # Merge them with \\n
                merged = line.rstrip('\n\r') + '\\n' + next_line.lstrip()
                new_lines.append(merged)
                i += 2
                continue
    new_lines.append(line)
    i += 1

with open('detect_apache_misconf.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
