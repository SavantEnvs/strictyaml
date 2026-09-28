"""Behavioral (known-answer) oracle for strictyaml.

strictyaml's upstream suite is written as hitchstory `.story` files driven by a
bespoke `hitch` engine that builds throwaway virtualenvs and needs network
access — not runnable inside the air-gapped commit image. This file is a
self-contained pytest oracle that asserts strictyaml's *documented behavior* on
known inputs (parse results, type coercion, round-trip, and rejection of
non-conforming YAML) — exactly the code paths the fuzz harness drives.

It is a real behavioral oracle: neutering strictyaml (e.g. making load() a
no-op / exit(0)) breaks these assertions, so the anti-reward-hack sabotage
check fails as required.
"""
from collections import OrderedDict

import pytest

import strictyaml
from strictyaml import (
    load,
    as_document,
    Map,
    MapPattern,
    Seq,
    Str,
    Int,
    Bool,
    YAMLError,
)


def test_load_scalar_default_is_str():
    # With no schema everything is a string.
    result = load("a: 1")
    assert result.data == {"a": "1"}
    assert isinstance(result.data["a"], str)


def test_load_mapping_multiple_keys():
    yaml = "a: 1\nb: 2\nc: 3\n"
    assert load(yaml).data == {"a": "1", "b": "2", "c": "3"}


def test_load_sequence():
    yaml = "- a\n- b\n- c\n"
    assert load(yaml).data == ["a", "b", "c"]


def test_load_nested():
    yaml = "a:\n  b: 1\n  c: 2\n"
    assert load(yaml).data == {"a": {"b": "1", "c": "2"}}


def test_int_schema_coercion():
    schema = Map({"a": Int()})
    result = load("a: 5", schema)
    assert result["a"].data == 5
    assert isinstance(result["a"].data, int)


def test_bool_schema_coercion():
    schema = Map({"flag": Bool()})
    assert load("flag: yes", schema)["flag"].data is True
    assert load("flag: no", schema)["flag"].data is False


def test_seq_schema():
    schema = Seq(Int())
    assert load("- 1\n- 2\n- 3\n", schema).data == [1, 2, 3]


def test_mappattern_schema():
    schema = MapPattern(Str(), Int())
    assert load("x: 1\ny: 2\n", schema).data == {"x": 1, "y": 2}


def test_round_trip_preserves_text():
    original = "a: 1\nb: 2\n"
    assert load(original).as_yaml() == original


def test_as_document_round_trip():
    doc = as_document(OrderedDict([("a", "1"), ("b", "2")]))
    assert doc.as_yaml() == "a: 1\nb: 2\n"


def test_as_document_nested():
    doc = as_document({"a": {"b": "c"}})
    assert load(doc.as_yaml()).data == {"a": {"b": "c"}}


def test_invalid_yaml_raises():
    # A duplicate key is non-conforming for strictyaml.
    with pytest.raises(YAMLError):
        load("a: 1\na: 2\n")


def test_schema_type_mismatch_raises():
    schema = Map({"a": Int()})
    with pytest.raises(YAMLError):
        load("a: not_an_int", schema)


def test_missing_required_key_raises():
    schema = Map({"a": Str(), "b": Str()})
    with pytest.raises(YAMLError):
        load("a: 1\n", schema)


def test_flow_style_rejected():
    # strictyaml deliberately rejects flow-style ({...}/[...]) YAML.
    with pytest.raises(YAMLError):
        load("{a: 1, b: 2}")


def test_yamlerror_is_exception():
    assert issubclass(strictyaml.YAMLError, Exception)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
