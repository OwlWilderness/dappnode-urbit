"""Bounded directly supervised HOST FIXTURE capture; not a Zig observer.

The trusted caller supplies executable/script pins and seals the returned receipt
hash out of band. Hashes are bindings, not signatures or evidence of target use.
No shell, diagnostic parser, response expansion or historical cache search.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess

MAX_BYTES = 8 * 1024 * 1024
MAX_PIN_BYTES = 128 * 1024 * 1024
MAX_ARG_BYTES = 128 * 1024
MAX_ARGS = 1024
TIMEOUT = 5


def nonlinked(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('absolute nonlinked path required')
    return path


def regular(path):
    path = nonlinked(path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('regular file required')
    return path


def file_pin(path):
    path = regular(path)
    if path.stat().st_size > MAX_PIN_BYTES:
        raise ValueError('pin byte limit')
    h = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            size += len(block)
            if size > MAX_PIN_BYTES:
                raise ValueError('pin byte limit')
            h.update(block)
    return {'sha256': h.hexdigest(), 'bytes': size}


def bounded(path):
    with regular(path).open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('capture byte limit')
    return data


def encoded(argv):
    return [base64.b64encode(os.fsencode(a)).decode('ascii') for a in argv]


def data_pin(data):
    return {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def check_pins(pins):
    if not isinstance(pins, dict) or not pins or len(pins) > 32:
        raise ValueError('explicit producer pins required')
    for name, expected in pins.items():
        if file_pin(name) != expected:
            raise ValueError('producer pin mismatch')


def run(argv, cwd):
    child = subprocess.Popen(argv, cwd=cwd, env={'PATH': '/usr/bin:/bin', 'LANG': 'C',
                             'PYTHONDONTWRITEBYTECODE': '1'}, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
    try:
        code = child.wait(timeout=TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        raise ValueError('fixture deadline') from exc
    record = {'argv_b64': encoded(argv), 'cwd_b64': encoded([str(cwd)])[0],
              'pid': child.pid, 'returncode': code}
    if code != 0:
        raise ValueError('unsuccessful fixture child')
    return record


def capture_host_fixture(*, cwd, dependency, exporter, linker, graph, binary, output, pins):
    """Observe three fresh, direct fixture children in dependency/export/link order.

    This API does not observe grandchildren, Zig make-phase callbacks or LLD.
    Caller may execute only separately authorized public host fixtures. An isolated
    non-adversarial directory is required; no hostile-writer guarantee is made.
    """
    cwd, graph, binary, output = map(Path, (cwd, graph, binary, output))
    for path in (cwd, graph, binary, output):
        nonlinked(path)
    if not cwd.is_dir() or any(p.parent != cwd for p in (graph, binary, output)) or len({graph, binary, output}) != 3:
        raise ValueError('isolated direct fixture paths required')
    check_pins(pins)
    for argv in (dependency, exporter, linker):
        if not isinstance(argv, list) or not argv or len(argv) > MAX_ARGS or any(not isinstance(a, (str, bytes)) or b'\0' in os.fsencode(a) for a in argv):
            raise ValueError('explicit bounded argv required')
        if sum(len(os.fsencode(a)) + 1 for a in argv) > MAX_ARG_BYTES:
            raise ValueError('argv byte limit')
        if os.fsdecode(argv[0]) not in pins:
            raise ValueError('unpinned executable')
        if len(argv) < 2 or os.fsdecode(argv[1]) not in pins:
            raise ValueError('pinned fixture script required')
    if output.exists() or output.is_symlink() or graph.exists() or binary.exists():
        raise ValueError('fresh capture/output required')
    output.mkdir()
    steps = [run(dependency, cwd), run(exporter, cwd)]
    graph_bytes = bounded(graph)
    value = json.loads(graph_bytes)
    if (not isinstance(value, dict) or set(value) != {'schema', 'modules', 'registrations'} or
            type(value['schema']) is not int or value['schema'] != 1 or
            not isinstance(value['modules'], list) or not value['modules'] or
            not isinstance(value['registrations'], list)):
        raise ValueError('invalid fixture graph')
    total = len(graph_bytes)
    (output/'graph.json').write_bytes(graph_bytes)
    files = {'graph.json': data_pin(graph_bytes)}
    responses = []
    for arg in linker[1:]:
        raw = os.fsencode(arg)
        if raw.startswith(b'@'):
            source = cwd / os.fsdecode(raw[1:])
            data = bounded(source)
            # No claim to implement LLVM's response grammar. Conservative host
            # fixture subset refuses every @ byte, including quoted occurrences.
            if b'@' in data:
                raise ValueError('nested/unsupported response content')
            total += len(data)
            if total > MAX_BYTES:
                raise ValueError('aggregate capture byte limit')
            name = 'response-' + str(len(responses)) + '.bin'
            (output/name).write_bytes(data)
            files[name] = data_pin(data)
            responses.append({'argument_b64': base64.b64encode(raw).decode('ascii'),
                              'source': str(source), 'file': name, 'pin': data_pin(data)})
    steps.append(run(linker, cwd))
    for response in responses:
        if file_pin(response['source']) != response['pin']:
            raise ValueError('response changed during execution')
    if bounded(graph) != graph_bytes:
        raise ValueError('graph changed during execution')
    binary_bytes = bounded(binary)
    total += len(binary_bytes)
    if total > MAX_BYTES:
        raise ValueError('aggregate capture byte limit')
    (output/'binary.bin').write_bytes(binary_bytes)
    files['binary.bin'] = data_pin(binary_bytes)
    check_pins(pins)
    if {p.name for p in output.iterdir()} != set(files):
        raise ValueError('retained evidence inventory changed')
    for name, expected in files.items():
        if file_pin(output/name) != expected:
            raise ValueError('retained evidence changed')
    receipt = {'schema': 1, 'evidence_class': 'observed-host-fixture',
               'target_authenticated': False, 'producer_pins': pins,
               'steps': steps, 'responses': responses, 'files': files,
               'limitations': ['no Zig graph observation', 'no descendant observation',
                               'no response expansion', 'isolated non-adversarial fixture only']}
    receipt_bytes = (json.dumps(receipt, sort_keys=True) + '\n').encode()
    if total + len(receipt_bytes) > MAX_BYTES:
        raise ValueError('aggregate receipt byte limit')
    (output/'receipt.json').write_bytes(receipt_bytes)
    return receipt


def verify_host_fixture(output, pins, receipt_pin):
    """Verify sealed fixture evidence, never elevate it to target provenance."""
    output = Path(output)
    if file_pin(output/'receipt.json') != receipt_pin:
        raise ValueError('untrusted receipt binding')
    result = json.loads(bounded(output/'receipt.json'))
    if type(result['schema']) is not int or result['schema'] != 1 or result['evidence_class'] != 'observed-host-fixture' or result['target_authenticated'] is not False:
        raise ValueError('unsupported evidence class')
    if result['producer_pins'] != pins:
        raise ValueError('wrong trusted producer')
    if {p.name for p in output.iterdir()} != set(result['files']) | {'receipt.json'}:
        raise ValueError('evidence inventory differs')
    total = regular(output/'receipt.json').stat().st_size
    for name, expected in result['files'].items():
        if Path(name).name != name or name in ('.', '..'):
            raise ValueError('noncanonical evidence name')
        total += regular(output/name).stat().st_size
        if total > MAX_BYTES:
            raise ValueError('aggregate verification byte limit')
        if file_pin(output/name) != expected:
            raise ValueError('retained evidence mismatch')
    return result
