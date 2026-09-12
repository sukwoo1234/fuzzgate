#!/usr/bin/env python3
"""R49/R55 class scan: find build-script lines that put bytes at an operational output.

grep cannot tell a destination argument from a source one, and neither can "the last token
on the line" - a 2026-09-12 review showed that version missing 48% of realistic spellings
because `cp "$src" "$OUT" || exit 1` (this repository's own idiom) pushes the destination
away from the end. So: join line continuations, split each logical line into command
segments on shell operators, pull redirections out of each segment, and only then ask what
the command writes to.

Output-shaped means the whole argument is one expansion of a variable whose name carries
OUT or BIN - not a path under it, not a STAGED_* staging variable, not a *_DIR directory.
Known limit, stated rather than hidden: a destination held in a differently named variable
(REPLAY, DEST) is invisible here, as is one built by aliasing (DEST="$OUT"; cc -o "$DEST").
"""
import re
import shlex
import sys

VAREXP = re.compile(r'^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$')
WRITERS = {'cp', 'mv', 'ln', 'install', 'rsync', 'objcopy', 'strip', 'tee'}
OPERATORS = re.compile(r'\|\||&&|[;|&]')
# A redirection token: optional fd, > or >>, optional space, target.
REDIR = re.compile(r'(?:[0-9]*|&)>>?')


def output_shaped(tok):
    m = VAREXP.match(tok)
    if not m:
        return False
    name = m.group(1)
    if name.startswith('STAGED'):
        return False          # the staging file is the point, not a violation
    if name.endswith('DIR'):
        return False          # a directory is not the binary
    return ('OUT' in name) or name.endswith('BIN') or '_BIN' in name


def logical_lines(path):
    """Yield (first_line_number, text) with backslash continuations joined."""
    buf, start = '', None
    for n, raw in enumerate(open(path, encoding='utf-8', errors='replace'), 1):
        line = raw.rstrip('\n')
        if start is None:
            start = n
        if line.endswith('\\'):
            buf += line[:-1] + ' '
            continue
        buf += line
        yield start, buf
        buf, start = '', None
    if buf:
        yield start, buf


def segments(code):
    """Split a logical line into command segments on shell operators."""
    return [s for s in OPERATORS.split(code) if s.strip()]


def destinations(seg):
    """Every path this command segment writes to, as raw tokens."""
    try:
        toks = shlex.split(seg, comments=False, posix=True)
    except ValueError:
        toks = seg.split()
    out, plain, i = [], [], 0
    while i < len(toks):
        t = toks[i]
        # Redirection written as its own token: `>` `$OUT`
        if REDIR.fullmatch(t) and i + 1 < len(toks):
            out.append(toks[i + 1]); i += 2; continue
        # Redirection glued to its target: `>$OUT`, `2>>$OUT`
        m = re.match(r'^(?:[0-9]*|&)>>?(.+)$', t)
        if m and not t.startswith('->'):
            out.append(m.group(1)); i += 1; continue
        if t.startswith('of='):        # dd
            out.append(t[3:]); i += 1; continue
        if t == '-o' and i + 1 < len(toks):
            out.append(toks[i + 1]); i += 2; continue
        if t.startswith('-o') and len(t) > 2:
            out.append(t[2:]); i += 1; continue
        plain.append(t); i += 1
    # cp/mv/install/...: the destination is the last non-option argument of the command
    if plain and plain[0] in WRITERS:
        args = [x for x in plain[1:] if not x.startswith('-')]
        if args:
            out.append(args[0] if plain[0] == 'tee' else args[-1])
    return out


def offenders(path):
    hits, seen = [], set()
    for n, code in logical_lines(path):
        stripped = code.strip()
        if stripped.startswith('#') or not stripped:
            continue
        if stripped.startswith('staged_commit '):
            continue
        code = re.sub(r'\s#(?=\s).*$', '', code)
        for seg in segments(code):
            for dest in destinations(seg):
                if output_shaped(dest) and n not in seen:
                    seen.add(n)
                    hits.append('%d:%s' % (n, stripped[:120]))
    return hits


if __name__ == '__main__':
    rc = 0
    for p in sys.argv[1:]:
        for h in offenders(p):
            print('%s\t%s' % (p, h))
            rc = 1
    sys.exit(rc)
