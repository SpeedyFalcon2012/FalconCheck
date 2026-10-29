"""Isolated parsing helper. Source/archives are treated solely as data."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
except (ImportError, ValueError, OSError):
    pass


def main():
    kind = sys.argv[1]
    try:
        if kind == 'python':
            from falcon_check import MAX_PYTHON_BYTES, analyze_python
            data = sys.stdin.buffer.read(MAX_PYTHON_BYTES + 1)
            if len(data) > MAX_PYTHON_BYTES:
                raise ValueError('Python source exceeds 2 MiB.')
            findings = analyze_python(data.decode('utf-8-sig'))
            result = {'status': 'NEEDS REVIEW' if findings else 'NO INDICATORS FOUND',
                      'findings': findings, 'coverage': 'Python analysis: selected calls, assignments, known-string f-strings, path joins, and supported sensitive-file to Requests/Session upload flows; limited local value tracking. No runtime or whole-program analysis.'}
        elif kind.startswith('executable-'):
            from falcon_executable import inspect_executable
            result = inspect_executable(sys.stdin.buffer, kind.split('-', 1)[1])
        else:
            from falcon_formats import archive_inventory
            result = archive_inventory(sys.stdin.buffer, kind)
    except Exception as error:
        result = {'status': 'NOT INSPECTED' if kind == 'python' else 'PARTIAL INSPECTION',
                  'findings': [], 'coverage': 'Analysis incomplete: ' + type(error).__name__,
                  'notes': [str(error)[:300] or 'Parser could not complete.']}
    print(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    main()
