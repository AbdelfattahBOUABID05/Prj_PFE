import re
import os

def parse_log_file(filepath):
    # الهيكل اللي غانحطو فيه البيانات
    segments = {
        'ERROR': [],
        'WARNING': [],
        'INFO': [],
        'DEBUG': []
    }
    
    # Regex باش نعرفو السطر واش فيه [ERROR] أو [WARNING] إلخ...
    # هاد التعبير كيقلب على الكلمات وسط السطر
    patterns = {
        'ERROR': re.compile(r'error|fail|critical|severe', re.IGNORECASE),
        'WARNING': re.compile(r'warning|warn', re.IGNORECASE),
        'INFO': re.compile(r'info', re.IGNORECASE),
        'DEBUG': re.compile(r'debug', re.IGNORECASE)
    }

    if not os.path.exists(filepath):
        return segments

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
                
            # كنقلبو فكل سطر على الكلمات المفتاحية
            found = False
            for level, pattern in patterns.items():
                if pattern.search(line):
                    segments[level].append(line)
                    found = True
                    break
            
            # إذا مالقينا والو، كنعتبروه INFO كافتراض
            if not found:
                segments['INFO'].append(line)
                
    return segments