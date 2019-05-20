import re


_RE_ALIAS = re.compile(r"(?P<user>(\w+[.|\w])*)@(?P<domain>(\w+[.])*\w+)")


def parse(un):
    m = _RE_ALIAS.match(un)
    if m is None:
        return None

    m = m.groupdict()

    return (m.get('user'), m['domain'])
