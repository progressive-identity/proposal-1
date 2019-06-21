import re

_RE_SCOPE = re.compile(r"^(?P<provider>[a-zA-Z_]+)(\.(?P<path>[a-zA-Z_\.]+))?(\[(?P<conds>.*)\])?\.(?P<fields>[\{\}a-zA-Z,_*]+)$")
_RE_SCOPE_COND = re.compile(r"^(?P<k>[a-zA-Z0-9_]+)(?P<op>(<=|>=|!=|<|>|=))(?P<v>[^,]+)$")


def split(scopes):
    main, consent = [], []

    for scope in scopes.split():
        if scope.startswith("?"):
            consent.append(scope[1:])
        else:
            main.append(scope)

    main.sort()
    consent.sort()

    return main, consent


class ScopeCondition:
    def __init__(self, cond, var, value):
        self.cond = cond
        self.var = var
        self.value = value

    def __repr__(self):
        return f"<ScopeCondition {self.var} {self.cond} {self.value!r}>"


def parse(scope):
    # XXX implemet better parsing

    m = _RE_SCOPE.match(scope)

    if not m:
        return None

    m = m.groupdict()
    provider, path, conds, fields = m['provider'], m['path'], m['conds'], m['fields']

    if conds:
        conds2 = []
        for cond in conds.split(','):
            cond_m = _RE_SCOPE_COND.match(cond)

            if not cond_m:
                raise ValueError("malformed scope")

            cond_m = cond_m.groupdict()
            k, op, v = cond_m['k'], cond_m['op'], cond_m['v']

            cond = ScopeCondition(op, k, v)

            conds2.append(cond)

        conds = conds2

    if fields != '*':
        if fields[0] == '{' and fields[-1] == '}':
            fields = fields[1:-1].split(',')
        else:
            fields = [fields]

    return provider, path, conds, fields
