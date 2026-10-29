"""Positive and negative cases for deliberately limited Python value tracking."""
import unittest
import falcon_check as scanner


class PythonFlowTests(unittest.TestCase):
    def test_assignment_expression_does_not_leave_stale_path(self):
        result = self.inspect('p = "/etc/shadow"\nif (p := "notes.txt"):\n pass\nopen(p)\n')
        self.assertEqual(result['findings'], [])

    def inspect(self, source):
        return scanner.analyze_bytes(source.encode(), 'example.py', 'python')

    def test_assignment_chain_reports_origin_and_use(self):
        result = self.inspect('base = "/etc/"\npath = base + "shadow"\nalias = path\nopen(alias)\n')
        finding = result['findings'][0]
        self.assertEqual((finding['rule'], finding['line']), ('sensitive-path', 4))
        self.assertEqual(finding['resolved'], '/etc/shadow')
        self.assertTrue(any('Line 1:' in step for step in finding['trace']))
        self.assertTrue(any('Line 3:' in step for step in finding['trace']))

    def test_safe_reassignment_removes_old_value(self):
        self.assertEqual(self.inspect('p = "/etc/shadow"\np = "notes.txt"\nopen(p)\n')['findings'], [])

    def test_unknown_reassignment_removes_old_value(self):
        self.assertEqual(self.inspect('p = "/etc/shadow"\np = input()\nopen(p)\n')['findings'], [])

    def test_shell_flag_and_command_list_variables(self):
        findings = self.inspect('import subprocess as sp\nflag = True\ncmd = ["crontab", "-l"]\nsp.run(cmd, shell=flag)\n')['findings']
        self.assertEqual({f['rule'] for f in findings}, {'startup', 'shell-command'})
        self.assertTrue(all(f.get('trace') for f in findings))

    def test_false_shell_flag_is_not_flagged(self):
        self.assertEqual(self.inspect('import subprocess\nx = False\nsubprocess.run("echo hello", shell=x)\n')['findings'], [])

    def test_conflicting_branch_values_are_unknown_after_join(self):
        source = 'if condition:\n p = "/etc/shadow"\nelse:\n p = "notes.txt"\nopen(p)\n'
        self.assertEqual(self.inspect(source)['findings'], [])

    def test_same_branch_value_can_be_traced(self):
        result = self.inspect('if condition:\n p = "/etc/shadow"\nelse:\n p = "/etc/shadow"\nopen(p)\n')
        self.assertEqual(result['findings'][0]['rule'], 'sensitive-path')

    def test_each_branch_call_is_checked(self):
        result = self.inspect('if condition:\n p = "/etc/shadow"\n open(p)\n')
        self.assertEqual(result['findings'][0]['line'], 3)

    def test_function_parameters_shadow_builtins(self):
        self.assertEqual(self.inspect('def f(eval, open):\n eval("hello")\n open("/etc/shadow")\n')['findings'], [])

    def test_local_binding_shadows_builtin_before_assignment(self):
        self.assertEqual(self.inspect('def f():\n eval("hello")\n eval = print\n')['findings'], [])

    def test_function_locals_do_not_leak(self):
        self.assertEqual(self.inspect('def f():\n p = "/etc/shadow"\nopen(p)\n')['findings'], [])

    def test_function_local_path_is_traced(self):
        result = self.inspect('def f():\n p = "/etc/shadow"\n open(p)\n')
        self.assertEqual(result['findings'][0]['line'], 3)

    def test_import_in_other_function_does_not_leak(self):
        source = 'def f():\n import os as thing\nthing.system("echo hello")\n'
        self.assertEqual(self.inspect(source)['findings'], [])

    def test_alias_reassignment_is_respected(self):
        source = 'import os\nos = object()\nos.system("echo hello")\n'
        self.assertEqual(self.inspect(source)['findings'], [])

    def test_callable_alias_is_traced(self):
        result = self.inspect('run = eval\nrun("2+2")\n')
        self.assertEqual(result['findings'][0]['rule'], 'dynamic-code')

    def test_deleted_and_mutated_values_are_not_stale(self):
        for body in ('del p', 'p[0] = "echo"', 'p.clear()', 'unknown(p)'):
            source = 'import subprocess\np = ["crontab", "-l"]\n' + body + '\nsubprocess.run(p)\n'
            self.assertEqual(self.inspect(source)['findings'], [], body)

    def test_comprehension_target_does_not_use_outer_path(self):
        source = 'p = "/etc/shadow"\n[open(p) for p in paths]\n'
        self.assertEqual(self.inspect(source)['findings'], [])

    def test_literal_text_without_selected_call_stays_unflagged(self):
        source = 'p = "/etc/" + "shadow"\nprint(p)\n'
        self.assertEqual(self.inspect(source)['findings'], [])


if __name__ == '__main__':
    unittest.main()
