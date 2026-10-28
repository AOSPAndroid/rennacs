"""Tests for the filter query language compiler."""

import pytest

from rennacs.query import QueryError, compile_query, tokenize


def test_empty_query_matches_all():
    assert compile_query("") == ("1", [])
    assert compile_query("   ") == ("1", [])


def test_port_is_integer_param():
    where, params = compile_query("port:22")
    assert where == "s.port = ?"
    assert params == [22]


def test_port_rejects_non_numeric():
    with pytest.raises(QueryError):
        compile_query("port:ssh")


def test_filters_are_anded():
    where, params = compile_query("product:nginx has_ssl:true")
    assert " AND " in where
    assert params == ["%nginx%", 1]


def test_free_text_uses_search_text():
    where, params = compile_query("openssh")
    assert where == "s.search_text LIKE ?"
    assert params == ["%openssh%"]


def test_negation_wraps_in_not():
    where, params = compile_query("-port:80")
    assert where == "NOT (s.port = ?)"
    assert params == [80]


def test_quoted_value_keeps_spaces():
    where, params = compile_query('org:"Google LLC"')
    assert params == ["%Google LLC%"]


def test_apostrophe_is_literal_not_a_quote():
    # single quotes are ordinary characters, not delimiters
    where, params = compile_query("obrien")
    where2, params2 = compile_query("product:O'Brien")
    assert params2 == ["%O'Brien%"]


def test_unbalanced_double_quote_errors():
    with pytest.raises(QueryError):
        compile_query('org:"unterminated')


def test_country_is_case_insensitive():
    where, _ = compile_query("country:us")
    assert "UPPER" in where


def test_net_compiles_to_integer_between():
    where, params = compile_query("net:192.168.1.0/24")
    assert "ip_int BETWEEN" in where
    assert len(params) == 2 and params[0] < params[1]


def test_net_rejects_bad_cidr():
    with pytest.raises(QueryError):
        compile_query("net:999.999.0.0/8")


def test_net_rejects_ipv6():
    with pytest.raises(QueryError):
        compile_query("net:2001:db8::/32")


def test_has_vuln_true_and_false():
    where_t, p_t = compile_query("has_vuln:true")
    where_f, p_f = compile_query("has_vuln:false")
    assert "IS NOT NULL" in where_t and p_t == []
    assert "IS NULL" in where_f and p_f == []


def test_vuln_filter_is_like():
    where, params = compile_query("vuln:CVE-2024-6387")
    assert where == "s.vuln_ids LIKE ?"
    assert params == ["%CVE-2024-6387%"]


def test_unknown_filter_rejected():
    with pytest.raises(QueryError):
        compile_query("bogus:1")


@pytest.mark.parametrize("payload", [
    'product:"x\';DROP TABLE services;--"',
    'org:"1\'; DELETE FROM hosts; --"',
])
def test_injection_payloads_stay_bound_params(payload):
    where, params = compile_query(payload)
    # no attacker text leaks into the SQL string; it only appears in bound params
    assert "DROP" not in where and "DELETE" not in where
    assert where.count("?") == len(params)


def test_tokenize_marks_negation_and_filter():
    (t,) = tokenize("-port:443")
    assert t.negate and t.filt == "port" and t.value == "443"
