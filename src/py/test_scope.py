import scope


def test_scope():
    provider, path, conds, fields = scope.parse("provider.path.to.resource[var1=value1].{field_a,field_b}")

    assert provider == "provider"
    assert path == "path.to.resource"
    assert conds[0].cond == "="
    assert conds[0].var == "var1"
    assert conds[0].value == "value1"
    assert fields[0] == "field_a"
    assert fields[1] == "field_b"


def test_scope_no_conds():
    provider, path, conds, fields = scope.parse("provider.path.to.resource.{field_a,field_b}")

    assert provider == "provider"
    assert path == "path.to.resource"
    assert conds is None
    assert fields[0] == "field_a"
    assert fields[1] == "field_b"


def test_scope_all_fields():
    provider, path, conds, fields = scope.parse("provider.path.to.resource[var1=value1].*")

    assert provider == "provider"
    assert path == "path.to.resource"
    assert conds[0].cond == "="
    assert conds[0].var == "var1"
    assert conds[0].value == "value1"
    assert fields == "*"


def test_scope_no_conds_all_fields():
    provider, path, conds, fields = scope.parse("provider.path.to.resource.*")

    assert provider == "provider"
    assert path == "path.to.resource"
    assert conds is None
    assert fields[0] == "*"


def test_scope_no_path():
    provider, path, conds, fields = scope.parse("provider[var1=value1].{field_a,field_b}")

    assert provider == "provider"
    assert path is None
    assert conds[0].cond == "="
    assert conds[0].var == "var1"
    assert conds[0].value == "value1"
    assert fields[0] == "field_a"
    assert fields[1] == "field_b"


def test_all_operator():
    OPS = ["=", "<", "<=", ">", ">=", "!="]

    conds = ",".join(f"var{i}{op}value{i}" for i, op in enumerate(OPS))
    s = f"provider.path.to.resource[{conds}].*"
    print(s)
    provider, path, conds, fields = scope.parse(s)

    assert provider == "provider"
    assert path == "path.to.resource"
    for i, (op, cond) in enumerate(zip(OPS, conds)):
        assert cond.cond == op
        assert cond.var == f"var{i}"
        assert cond.value == f"value{i}"

    assert fields == "*"
