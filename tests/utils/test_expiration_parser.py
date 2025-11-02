from datetime import timedelta

from app.utils.helpers.expiration_parser import parse_expiration


def test_parse_minutes_suffix():
    assert parse_expiration("5m") == timedelta(minutes=5)


def test_parse_hours_suffix():
    assert parse_expiration("2h") == timedelta(hours=2)


def test_parse_days_suffix():
    assert parse_expiration("1d") == timedelta(days=1)


def test_parse_no_suffix_defaults_to_minutes():
    assert parse_expiration("30") == timedelta(minutes=30)
