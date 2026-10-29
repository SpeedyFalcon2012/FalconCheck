"""Small, bounded abstract interpreter for selected Python source clues.

No source is evaluated or imported. Unsupported values become unknown.
"""
import ast
import os.path
from pathlib import PurePath
from dataclasses import dataclass


@dataclass(frozen=True)
class Value:
    kind: str
    data: object = None
    trace: tuple = ()


UNKNOWN = Value('unknown')
BUILTINS = {'eval', 'exec', 'open', 'input'}
SHELL = {'os.system', 'os.popen'}
SUBPROCESS = {'subprocess.run', 'subprocess.call', 'subprocess.Popen', 'subprocess.check_call', 'subprocess.check_output'}
FILES = {'open', 'builtins.open', 'io.open', 'os.open', 'pathlib.Path'}
DECODERS = {'base64.b64decode', 'base64.standard_b64decode', 'base64.urlsafe_b64decode', 'binascii.a2b_base64'}
UPLOADS = {'requests.post', 'requests.put', 'requests.patch'}
UPLOADS |= {'requests.Session().' + method for method in ('post', 'put', 'patch')}
SESSIONS = {'requests.Session', 'requests.session', 'requests.sessions.Session'}
READERS = {'open', 'builtins.open', 'io.open'}


def trace_for(value, node, label):
    if value.kind == 'unknown':
        return value
    step = 'Line {}: {}'.format(node.lineno, label)
    return Value(value.kind, value.data, (value.trace + (step,))[-8:])


def analyze(text, rules, max_nodes):
    tree = ast.parse(text)
    if sum(1 for _ in ast.walk(tree)) > max_nodes:
        raise ValueError('Python syntax tree exceeds the 100,000-node limit')
    definitions = {key: (title, pattern, why) for key, title, pattern, why in rules}
    findings = {}
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def upload(node, called, payload, destination, argument):
        key = 'sensitive-upload:{}:{}'.format(node.lineno, node.col_offset)
        if key in findings:
            return
        if sum(item['rule'] == 'sensitive-upload' for item in findings.values()) >= 20:
            raise ValueError('More than 20 sensitive upload findings; analysis stopped at its finding budget.')
        endpoint = destination.data if destination.kind == 'str' else '(destination could not be resolved)'
        item = {'rule': 'sensitive-upload', 'id': key, 'line': node.lineno,
                'title': 'Potential sensitive-file upload',
                'basis': 'Statically traced file data passed to a supported network call',
                'evidence': lines[node.lineno - 1].strip()[:200],
                'resolved': payload.data,
                'destination': endpoint[:300],
                'source_fact': 'The file contains a call expression at line {}. Scanning did not execute it.'.format(node.lineno),
                'inference': 'Under the supported Python and library semantics, the {} argument carries data or a readable handle from {} into {}.'.format(argument, payload.data, called),
                'legitimate_use': 'An authorized backup or transfer can use this same pattern. Confirm both permission to send this file and the intended recipient; a familiar-looking URL alone is not authorization.',
                'trace': list(payload.trace) + ['Line {}: supplied to {}'.format(node.lineno, called)],
                'why': 'This code connects a sensitive file read (or readable file handle) to an HTTP payload. It may transmit credentials or other sensitive data.',
                'uncertainty': 'This is a possible source-code flow, not observed transmission. Branches, import identity, authorization, and runtime success are not established. A deliberate backup may be legitimate.',
                'remediation': 'Review whether this upload is intended and the destination is authorized. For eligible standalone calls, Preview fix can remove that call in a separate copy.',
                'patch_span': None}
        parent = parents.get(node)
        # Only entire standalone call statements, not return values, expressions,
        # semicolon-separated statements, decorators, or one-line suites.
        prefix = lines[node.lineno - 1].encode('utf-8')[:node.col_offset]
        suffix = lines[node.end_lineno - 1].encode('utf-8')[node.end_col_offset:].strip()
        if isinstance(parent, ast.Expr) and parent.value is node and not prefix.strip() and (not suffix or suffix.startswith(b'#')):
            item['patch_span'] = [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]
        findings[key] = item

    def add(key, node, value=None):
        if key in findings:
            return
        title, pattern, why = definitions[key]
        item = {'rule': key, 'title': title, 'why': why, 'line': node.lineno,
                'evidence': lines[node.lineno - 1].strip()[:200],
                'basis': 'Selected Python call syntax'}
        if value and value.trace:
            item['basis'] = 'Statically traced value used by a selected call'
            item['trace'] = list(value.trace) + ['Line {}: used here'.format(node.lineno)]
            if value.kind in ('str', 'path', 'list', 'bool'):
                item['resolved'] = str(value.data)[:200]
        findings[key] = item

    def name(node, env, depth=0):
        if depth > 32:
            return ''
        if isinstance(node, ast.Name):
            if node.id in env:
                symbol = env[node.id]
                return symbol.data if symbol.kind == 'name' else ''
            return node.id if node.id in BUILTINS else ''
        if isinstance(node, ast.Attribute):
            base = name(node.value, env, depth + 1)
            if base:
                return base + '.' + node.attr
            receiver = (env.get(node.value.id, UNKNOWN) if isinstance(node.value, ast.Name) else
                        value(node.value, env, depth + 1) if isinstance(node.value, ast.Call) else UNKNOWN)
            if receiver.kind == 'session' and node.attr in ('post', 'put', 'patch'):
                return 'requests.Session().' + node.attr
        return ''

    def joined(values, node, kind, label, joiner):
        if not values or len(values) > 32 or any(v.kind not in ('str', 'path') for v in values):
            return UNKNOWN
        if sum(len(v.data) for v in values) > 4096:
            return UNKNOWN
        result = joiner(*(v.data for v in values))
        if len(result) > 4096:
            return UNKNOWN
        steps = tuple(step for v in values for step in v.trace)[-8:]
        return trace_for(Value(kind, result, steps), node, label)

    def value(node, env, depth=0):
        if node is None or depth > 32:
            return UNKNOWN
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and len(node.value) <= 4096:
                return Value('str', node.value)
            if isinstance(node.value, bool):
                return Value('bool', node.value)
        if isinstance(node, ast.Name):
            return env.get(node.id, Value('name', node.id) if node.id in BUILTINS else UNKNOWN)
        if isinstance(node, ast.Attribute):
            resolved = name(node, env, depth + 1)
            return Value('name', resolved) if resolved else UNKNOWN
        if isinstance(node, ast.JoinedStr):
            parts = []
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    # Only known strings and no format specification. No user
                    # objects, __format__, eval, or source function calls.
                    item = value(part.value, env, depth + 1)
                    if item.kind != 'str' or part.format_spec is not None or part.conversion not in (-1, 115, 114, 97):
                        return UNKNOWN
                    conversion = {114: repr, 97: ascii}.get(part.conversion, str)
                    parts.append(Value('str', conversion(item.data), item.trace))
                else:
                    parts.append(value(part, env, depth + 1))
            return joined(parts, node, 'str', 'builds a string from known f-string parts', lambda *parts: ''.join(parts))
        if isinstance(node, ast.Call):
            called = name(node.func, env, depth + 1)
            if called in SESSIONS and not node.args and not node.keywords:
                return trace_for(Value('session', (node.lineno, node.col_offset)), node, 'constructs a Requests session')
            if called in ('os.path.join', 'posixpath.join') and not node.keywords:
                import posixpath
                joiner = posixpath.join if called == 'posixpath.join' else os.path.join
                return joined([value(arg, env, depth + 1) for arg in node.args], node, 'str', 'joins known path components', joiner)
            if called == 'pathlib.Path':
                if node.keywords:
                    return UNKNOWN
                return joined([value(arg, env, depth + 1) for arg in node.args], node, 'path', 'constructs a Path from known components', lambda *parts: str(PurePath(*parts)))
            path_node = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg in ('file', 'path')), None)
            path = value(path_node, env, depth + 1)
            if called in READERS and path.kind in ('str', 'path') and definitions['sensitive-path'][1].search(path.data):
                mode_node = node.args[1] if len(node.args) > 1 else next((kw.value for kw in node.keywords if kw.arg == 'mode'), None)
                mode = Value('str', 'r') if mode_node is None else value(mode_node, env, depth + 1)
                if mode.kind == 'str' and ('r' in mode.data or '+' in mode.data):
                    return trace_for(Value('file', path.data, path.trace), node, 'opens sensitive path for reading: ' + path.data)
            if isinstance(node.func, ast.Attribute):
                base = value(node.func.value, env, depth + 1)
                if base.kind == 'path' and node.func.attr == 'joinpath' and not node.keywords:
                    return joined([base] + [value(arg, env, depth + 1) for arg in node.args], node, 'path', 'joins known Path components', lambda *parts: str(PurePath(*parts)))
                if base.kind == 'path' and node.func.attr == 'open' and definitions['sensitive-path'][1].search(base.data):
                    mode_node = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == 'mode'), None)
                    mode = Value('str', 'r') if mode_node is None else value(mode_node, env, depth + 1)
                    if mode.kind == 'str' and ('r' in mode.data or '+' in mode.data):
                        return trace_for(Value('file', base.data, base.trace), node, 'opens sensitive Path for reading: ' + base.data)
                if base.kind == 'file' and node.func.attr in ('read', 'readline', 'readlines'):
                    return trace_for(Value('sensitive', base.data, base.trace), node, 'reads file contents')
                if base.kind == 'path' and node.func.attr in ('read_text', 'read_bytes') and definitions['sensitive-path'][1].search(base.data):
                    return trace_for(Value('sensitive', base.data, base.trace), node, 'reads sensitive path: ' + base.data)
        if isinstance(node, ast.Dict) and len(node.values) <= 32:
            for child in node.values:
                abstract = value(child, env, depth + 1)
                if abstract.kind in ('sensitive', 'file', 'sensitive-container'):
                    return Value('sensitive-container', abstract.data, abstract.trace)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = value(node.left, env, depth + 1), value(node.right, env, depth + 1)
            if left.kind == right.kind == 'str' and len(left.data) + len(right.data) <= 4096:
                return Value('str', left.data + right.data, (left.trace + right.trace)[-8:])
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left, right = value(node.left, env, depth + 1), value(node.right, env, depth + 1)
            if left.kind == 'path' and right.kind in ('str', 'path'):
                return joined([left, right], node, 'path', 'joins a Path with /', lambda *parts: str(PurePath(*parts)))
        if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) <= 32:
            items = [value(child, env, depth + 1) for child in node.elts]
            for item in items:
                if item.kind in ('sensitive', 'file', 'sensitive-container'):
                    return Value('sensitive-container', item.data, item.trace)
            if all(item.kind == 'str' for item in items) and sum(len(item.data) for item in items) <= 4096:
                return Value('list', tuple(item.data for item in items), tuple(step for item in items for step in item.trace)[-8:])
        return UNKNOWN

    def forget_container(env, identifier):
        previous = env.get(identifier, UNKNOWN)
        if previous.kind in ('list', 'sensitive-container', 'session'):
            # Alias identity is not modeled. Forget every potentially aliased
            # container with the same abstract contents after a mutation/use.
            for key, item in list(env.items()):
                if (item.kind, item.data) == (previous.kind, previous.data):
                    env[key] = UNKNOWN
        env[identifier] = UNKNOWN

    def bind(target, abstract, env, node):
        if isinstance(target, ast.Name):
            env[target.id] = trace_for(abstract, node, 'assigned to ' + target.id)
        elif isinstance(target, (ast.List, ast.Tuple)):
            for child in target.elts:
                bind(child, UNKNOWN, env, node)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            # Mutation invalidates the base object; don't retain stale literals.
            base = target.value
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            if isinstance(base, ast.Name):
                forget_container(env, base.id)

    def inspect_expr(node, env):
        if node is None:
            return
        if isinstance(node, ast.NamedExpr):
            inspect_expr(node.value, env)
            bind(node.target, value(node.value, env), env, node)
            return
        if isinstance(node, ast.Lambda):
            child = dict(env)
            for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                child[arg.arg] = UNKNOWN
            if node.args.vararg:
                child[node.args.vararg.arg] = UNKNOWN
            if node.args.kwarg:
                child[node.args.kwarg.arg] = UNKNOWN
            inspect_expr(node.body, child)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            child = dict(env)
            for generator in node.generators:
                inspect_expr(generator.iter, child)
                bind(generator.target, UNKNOWN, child, generator.target)
                for test in generator.ifs:
                    inspect_expr(test, child)
            for field in ('elt', 'key', 'value'):
                inspect_expr(getattr(node, field, None), child)
            return
        for child in ast.iter_child_nodes(node):
            inspect_expr(child, env)
        if not isinstance(node, ast.Call):
            return
        called = name(node.func, env)
        if called in UPLOADS and not any(isinstance(arg, ast.Starred) for arg in node.args) and all(kw.arg is not None for kw in node.keywords):
            positional_names = ('url', 'data', 'json') if called.endswith('.post') else ('url', 'data')
            payload_nodes = [(label, arg) for label, arg in zip(positional_names, node.args) if label != 'url']
            payload_nodes += [(kw.arg, kw.value) for kw in node.keywords if kw.arg in ('data', 'json', 'files', 'params')]
            destination_node = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == 'url'), None)
            for argument, payload_node in payload_nodes:
                payload = value(payload_node, env)
                if payload.kind in ('sensitive', 'file', 'sensitive-container'):
                    upload(node, called, payload, value(destination_node, env), argument)
                    break
        args = [value(arg, env) for arg in node.args] + [value(arg.value, env) for arg in node.keywords]
        if called == 'pathlib.Path':
            # Match the constructed path, not a discarded earlier component.
            args = [value(node, env)]
        if called in {'eval', 'exec', 'builtins.eval', 'builtins.exec'}:
            add('dynamic-code', node, args[0] if args else None)
        if called in DECODERS:
            add('encoded-content', node)
        shell_flag = next((value(arg.value, env) for arg in node.keywords if arg.arg == 'shell'), UNKNOWN)
        if called in SHELL or (called in SUBPROCESS and shell_flag.kind == 'bool' and shell_flag.data is True):
            add('shell-command', node, shell_flag)
        if called in FILES | SHELL | SUBPROCESS:
            keys = ['sensitive-path', 'startup']
            if called in SHELL | SUBPROCESS:
                keys += ['download-shell', 'encoded-content', 'powershell-encoded']
            for argument in args:
                text_value = argument.data if argument.kind in ('str', 'path') else (' '.join(argument.data) if argument.kind == 'list' else None)
                if text_value is not None:
                    for key in keys:
                        if definitions[key][1].search(text_value):
                            add(key, node, argument)
        # Report a selected Path read even when the upload is later removed.
        produced = value(node, env)
        if produced.kind in ('file', 'sensitive') and isinstance(node.func, ast.Attribute):
            base = value(node.func.value, env)
            if base.kind == 'path':
                add('sensitive-path', node, Value('str', base.data, produced.trace))
        # Unknown calls can invalidate mutable containers or session identity.
        targets = list(node.args)
        if isinstance(node.func, ast.Attribute):
            targets.append(node.func.value)
        targets += [arg.value for arg in node.keywords]
        for target in targets:
            if isinstance(target, ast.Name) and env.get(target.id, UNKNOWN).kind in ('list', 'sensitive-container'):
                forget_container(env, target.id)
            if isinstance(target, ast.Name) and env.get(target.id, UNKNOWN).kind == 'session' and called not in UPLOADS:
                forget_container(env, target.id)

    def merge(env, branches):
        keys = set(env).union(*(set(branch) for branch in branches))
        for key in keys:
            candidates = [branch.get(key, UNKNOWN) for branch in branches]
            first = candidates[0]
            if all((item.kind, item.data) == (first.kind, first.data) for item in candidates):
                trace = first.trace if all(item.trace == first.trace for item in candidates) else (
                    'Same value inferred on each analyzed branch for ' + key,)
                env[key] = Value(first.kind, first.data, trace)
            else:
                env[key] = UNKNOWN

    def local_bindings(body):
        result = set()
        def visit(node):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                result.add(node.name)
                return
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                result.add(node.id)
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                result.update(item.asname or (item.name.split('.')[0] if isinstance(node, ast.Import) else item.name) for item in node.names)
            for child in ast.iter_child_nodes(node):
                visit(child)
        for statement in body:
            visit(statement)
        return result

    def statements(body, env):
        for node in body:
            if isinstance(node, ast.Import):
                for item in node.names:
                    env[item.asname or item.name.split('.')[0]] = Value('name', item.name if item.asname else item.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                for item in node.names:
                    if item.name == '*':
                        env.clear()
                        env.update({key: UNKNOWN for key in BUILTINS})
                    else:
                        env[item.asname or item.name] = (Value('name', node.module + '.' + item.name)
                                                        if node.level == 0 and node.module else UNKNOWN)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                inspect_expr(node.value, env)
                known = value(node.value, env)
                for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    bind(target, known, env, node)
            elif isinstance(node, ast.AugAssign):
                inspect_expr(node.value, env)
                bind(node.target, UNKNOWN, env, node)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    bind(target, UNKNOWN, env, node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for expr in node.decorator_list + node.args.defaults + [d for d in node.args.kw_defaults if d is not None]:
                    inspect_expr(expr, env)
                env[node.name] = UNKNOWN
                # Retain import/callable names, not mutable captured values.
                child = {key: val if val.kind == 'name' else UNKNOWN for key, val in env.items()}
                child.update({key: UNKNOWN for key in local_bindings(node.body)})
                for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                    child[arg.arg] = UNKNOWN
                for arg in (node.args.vararg, node.args.kwarg):
                    if arg:
                        child[arg.arg] = UNKNOWN
                statements(node.body, child)
            elif isinstance(node, ast.ClassDef):
                for expr in node.bases + node.decorator_list:
                    inspect_expr(expr, env)
                statements(node.body, dict(env))
                env[node.name] = UNKNOWN
            elif isinstance(node, ast.If):
                inspect_expr(node.test, env)
                branches = [dict(env), dict(env)]
                statements(node.body, branches[0])
                statements(node.orelse, branches[1])
                merge(env, branches)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                inspect_expr(node.iter if hasattr(node, 'iter') else node.test, env)
                child = dict(env)
                child.update({key: UNKNOWN for key in local_bindings(node.body)})
                if hasattr(node, 'target'):
                    bind(node.target, UNKNOWN, child, node)
                statements(node.body, child)
                merge(env, [env.copy(), child])
                statements(node.orelse, env)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    inspect_expr(item.context_expr, env)
                    if item.optional_vars:
                        bind(item.optional_vars, value(item.context_expr, env), env, node)
                statements(node.body, env)
            elif isinstance(node, ast.Try):
                branches = [dict(env)]
                statements(node.body, branches[0])
                statements(node.orelse, branches[0])
                for handler in node.handlers:
                    child = dict(env)
                    child.update({key: UNKNOWN for key in local_bindings(node.body)})
                    if handler.name:
                        child[handler.name] = UNKNOWN
                    statements(handler.body, child)
                    branches.append(child)
                merge(env, branches)
                statements(node.finalbody, env)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                for key in node.names:
                    env[key] = UNKNOWN
            else:
                # Unsupported compound statements are not simulated. Forget
                # affected bindings so later calls don't inherit stale values.
                inspect_expr(node, env)
                for key in local_bindings([node]):
                    env[key] = UNKNOWN
    statements(tree.body, {})
    return sorted(findings.values(), key=lambda finding: (finding['line'], finding['rule']))
