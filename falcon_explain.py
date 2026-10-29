"""Plain-language summaries shared by the app and CLI."""


def checks(result):
    if result.get('checks'):
        return result['checks']
    mode = result.get('mode', 'auto')
    if mode == 'combined':
        return [('Built-in inspection', 'NOT COMPLETED'), ('Malware scan (ClamAV)', 'NOT COMPLETED')]
    if mode == 'antivirus':
        return [('Malware scan (ClamAV)', result['status']), ('Built-in inspection', 'NOT REQUESTED')]
    return [('Built-in inspection', result['status']), ('Malware scan (ClamAV)', 'NOT RUN — this mode uses built-in checks only')]


def meaning(result):
    status = result['status']
    if status == 'THREAT REPORTED':
        return 'ClamAV reported a detection. Do not run the file while you investigate; false positives are possible.'
    if status == 'NEEDS REVIEW':
        return 'Selected clues need review. They can occur in legitimate programs and do not establish malicious behavior.'
    if status == 'NO THREATS REPORTED':
        return 'ClamAV completed its scan and reported no threats within its coverage. This is not a guarantee of safety.'
    if status == 'NO INDICATORS FOUND':
        return 'The selected built-in rules found no clues. This result alone does not check the file against a malware database.'
    if status == 'BASIC INSPECTION':
        return 'Limited static inspection only; this is not a malware scan. No selected review clue was found within that coverage.'
    if status == 'CANCELLED':
        return 'The scan was cancelled. It has no completed overall result.'
    if status == 'ANTIVIRUS UNAVAILABLE':
        return 'No malware scan ran. Open Antivirus setup to check the engine and signatures.'
    return 'Some requested checks did not complete. Read the check statuses and coverage before drawing conclusions.'


def evidence_kind(finding):
    if finding.get('basis'):
        return finding['basis']
    if finding['rule'].startswith('string-'):
        return 'Embedded text only — not observed behavior'
    if finding['rule'].startswith(('elf-', 'pe-')):
        return 'Executable build property — not a malware signature'
    if finding['rule'].startswith('archive-'):
        return 'Archive name/metadata — contents not analyzed'
    return 'Text pattern — context needs review'


def next_step(result):
    if result['status'] == 'THREAT REPORTED':
        return 'Keep the file unopened. Review the exact ClamAV detection and confirm the download source.'
    if any(f.get('patch_span') for f in result.get('findings', [])):
        return 'Review the sensitive-file upload evidence and destination. Preview fix can propose removing a supported standalone call in a separate copy; other risks and intended functionality still need review.'
    if any('UNAVAILABLE' in status for label, status in checks(result) if label.startswith('Malware')):
        return 'Open Antivirus setup, set up the engine and signatures, then rerun Recommended scan.'
    if result.get('findings'):
        return 'Read each evidence type and trace. Determine whether the operation makes sense for this file; a clue is not a diagnosis.'
    if result['status'] in ('NOT INSPECTED', 'PARTIAL INSPECTION'):
        return 'Resolve the reported limit or error, or use another supported check. Do not treat an incomplete result as clearance.'
    if result.get('mode') != 'antivirus' and not result.get('checks'):
        return 'Use Recommended scan to request both built-in inspection and a ClamAV malware check.'
    return 'Consider the download source and the stated coverage. No scan can certify a file as safe.'
