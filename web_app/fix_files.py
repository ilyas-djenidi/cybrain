import sys

files = ['code_analyzer.py', 'detect_apache_misconf.py', 'report_generator.py', 'ai_agent.py', 'network_recon.py']
for f in files:
    try:
        with open(f, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # We handle replacing \" with "
        content = content.replace('\\"', '"')
        
        # We replace \\n with actual newline
        # actually, replace literal \n with newline
        content = content.replace('\\n', '\n')
        
        # We replace literal \\t with tab
        content = content.replace('\\t', '\t')
        
        # We replace literal \\r with carriage return
        content = content.replace('\\r', '\n')
        
        with open(f, 'w', encoding='utf-8') as file:
            file.write(content)
        print(f"Fixed {f}")
    except Exception as e:
        print(f"Error on {f}: {e}")
