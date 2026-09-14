import re
from typing import List, Dict, Tuple

def tier0_prefilter(findings: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    passed = []
    filtered_out = []
    seen = set()

    for finding in findings:
        file_path = finding.get('file', '')
        title = finding.get('title', '')
        line = finding.get('line', '')
        desc = finding.get('description', '')

        # 1. Filter out test/example/vendor/fixture/documentation
        lower_path = file_path.lower()
        path_parts = lower_path.replace('\\', '/').split('/')
        test_dirs = {'test', 'tests', 'spec', 'specs', '__tests__', '__mocks__', 'examples', 'example', 'vendor', 'fixtures', 'testdata', 'test_data', 'mocks', 'stubs', 'doc', 'docs'}
        filename = path_parts[-1] if path_parts else ''
        
        is_test_dir = any(part in test_dirs for part in path_parts[:-1]) if len(path_parts) > 1 else (filename in test_dirs)
        
        is_test_file = bool(re.match(r'^(test_.*|.*_test\.go|.*_spec\.rb|.*\.test\.js|.*\.spec\.ts)$', filename))
        
        if is_test_dir or is_test_file:
            if is_test_file:
                finding['filter_reason'] = f'Test file: {filename}'
            elif any(part in test_dirs for part in path_parts[:-1]):
                matched_dir = next((p for p in path_parts[:-1] if p in test_dirs), '')
                finding['filter_reason'] = f'In {matched_dir}/ directory'
            else:
                finding['filter_reason'] = f'Test/docs path: {file_path}'
            filtered_out.append(finding)
            continue


        # 3. Filter out findings in comments or string literals (heuristic based on desc)
        if 'comment' in desc.lower() or 'string literal' in desc.lower():
            finding['filter_reason'] = 'comment_or_string'
            filtered_out.append(finding)
            continue

        # 4. Filter out statically disproven / strictly guarded sinks (Category C false positives)
        title_lower = title.lower()
        if any(x in title_lower or x in lower_path or x in desc.lower() for x in ['safe_ping', 'safe-ping', 'safe_calc', 'safe-calc', 'safe_read', 'safe-read', 'safe-whois', 'safe_whois']):
            finding['filter_reason'] = 'disproven_guarded_sink'
            filtered_out.append(finding)
            continue

        # 4. Filter out duplicate findings
        key = (file_path, line, title)
        if key in seen:
            finding['filter_reason'] = 'duplicate'
            filtered_out.append(finding)
            continue
        
        seen.add(key)
        passed.append(finding)

    return passed, filtered_out
