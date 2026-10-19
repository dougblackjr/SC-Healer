"""Small non-executing PHP serialization parser for WordPress cron arrays.

No PHP objects, custom objects, references, or coercion. Strings stay bytes so
serialized lengths remain correct for non-ASCII values.
"""

from dataclasses import dataclass
import re


@dataclass
class Array:
    pairs: list


@dataclass
class Scalar:
    raw: bytes
    value: object


def loads(data):
    if len(data) > 16 * 1024 * 1024:
        raise ValueError('Serialized value exceeds size budget')
    pos = 0
    count = 0

    def take(size):
        nonlocal pos
        value = data[pos:pos + size]
        if len(value) != size:
            raise ValueError('Truncated serialization')
        pos += size
        return value

    def expect(value):
        if take(len(value)) != value:
            raise ValueError('Malformed serialization')

    def until(delimiter):
        nonlocal pos
        end = data.find(delimiter, pos, pos + 128)
        if end < 0:
            raise ValueError('Malformed scalar length/value')
        value = data[pos:end]
        pos = end + len(delimiter)
        return value

    def number(delimiter):
        raw = until(delimiter)
        if not re.fullmatch(rb'0|[1-9][0-9]*', raw):
            raise ValueError('Invalid nonnegative length')
        return int(raw)

    def parse(depth=0):
        nonlocal count
        count += 1
        if depth > 64 or count > 200000:
            raise ValueError('Serialization nesting/item budget reached')
        start = pos
        kind = take(1)
        if kind == b'N':
            expect(b';')
            return Scalar(b'N;', None)
        expect(b':')
        if kind == b's':
            length = number(b':')
            expect(b'"')
            value = take(length)
            expect(b'";')
            return Scalar(data[start:pos], value)
        if kind == b'a':
            size = number(b':')
            if size > 100000:
                raise ValueError('Array item budget reached')
            expect(b'{')
            pairs, keys = [], set()
            for _ in range(size):
                key, value = parse(depth + 1), parse(depth + 1)
                if not isinstance(key, Scalar) or type(key.value) not in (int, bytes):
                    raise ValueError('Invalid array key')
                if key.value in keys:
                    raise ValueError('Duplicate array key')
                keys.add(key.value)
                pairs.append((key, value))
            expect(b'}')
            return Array(pairs)
        if kind in (b'i', b'b', b'd'):
            value = until(b';')
            if kind == b'i':
                if not re.fullmatch(rb'-?(?:0|[1-9][0-9]*)', value):
                    raise ValueError('Invalid integer')
                parsed = int(value)
            elif kind == b'b':
                if value not in (b'0', b'1'):
                    raise ValueError('Invalid boolean')
                parsed = value == b'1'
            else:
                parsed = float(value)
            return Scalar(data[start:pos], parsed)
        raise ValueError('Objects/references and unsupported PHP types are rejected')

    result = parse()
    if pos != len(data):
        raise ValueError('Trailing serialized data')
    return result


def dumps(node):
    if isinstance(node, Scalar):
        return node.raw
    return b'a:' + str(len(node.pairs)).encode() + b':{' + b''.join(
        dumps(key) + dumps(value) for key, value in node.pairs) + b'}'


def cron_hooks(data):
    cron = loads(data)
    if not isinstance(cron, Array):
        raise ValueError('Cron is not a serialized array')
    hooks = set()
    for key, value in cron.pairs:
        if key.value == b'version':
            continue
        if type(key.value) is not int or not isinstance(value, Array):
            raise ValueError('Unexpected cron structure')
        for hook, events in value.pairs:
            if not isinstance(hook.value, bytes) or not isinstance(events, Array):
                raise ValueError('Unexpected cron event structure')
            hooks.add(hook.value.decode('utf-8', errors='strict'))
    return sorted(hooks)


def remove_hooks(data, hooks):
    known = set(cron_hooks(data))
    if not set(hooks) <= known:
        raise ValueError('Selected cron hook was not found')
    wanted = {hook.encode() for hook in hooks}
    cron = loads(data)
    retained = []
    for key, value in cron.pairs:
        if key.value == b'version':
            retained.append((key, value))
            continue
        value.pairs = [(hook, events) for hook, events in value.pairs if hook.value not in wanted]
        if value.pairs:
            retained.append((key, value))
    return dumps(Array(retained))
