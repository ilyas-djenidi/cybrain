import sys

with open('detect_apache_misconf.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the newline count that broke around line 142
content = content.replace("m.start()].count(\"\\n\")", "m.start()].count(\"\\\\n\")")
# But wait, my fix_detect.py already merged them into literally 'm.start()].count(\"\\n\")'. 
# Let me just forcibly replace any count(\"\\n\") with count(\"\\\\n\").
# Actually, the string in python with actual newline is \"\\n\", but the code needs the explicit escape sequence.
# Just to be safe, if we have count(\" followed by actual newline followed by \") it should become count(\"\\\\n\")
content = content.replace('count(\"\\n\")', 'count(\"\\\\n\")')

# Fix line 343: r"(password|passwd|secret)\s*=\s*['"][^'"]{4,}['"]"
content = content.replace(
    'r"(password|passwd|secret)\\s*=\\s*[\'\"][^\'\"]{4,}[\'\"]"',
    'r"(password|passwd|secret)\\s*=\\s*[\\\'\\"][^\\\'\\"]{4,}[\\\'\\"]"'
)
# Actually the search might just literally be:
content = content.replace('[\'\"]', '[\\\\\'\\\\\"]')
content = content.replace('[^\'\"]', '[^\\\\\'\\\\\"]')

# Let's also fix the header Access-Control-Allow-Origin wildcard
content = content.replace('r\"Access-Control-Allow-Origin\\s+[\'\"]?\\*\"', 'r\"Access-Control-Allow-Origin\\s+[\\\\\'\\\\\"]?\\*\"')

with open('detect_apache_misconf.py', 'w', encoding='utf-8') as f:
    f.write(content)
