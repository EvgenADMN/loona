# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Cron expressions: when a schedule fires.

The usual five fields - minute, hour, day of month, month, day of week - with
``*``, lists, ranges, steps and English names (``0 3 * * mon-fri``), plus
@hourly, @daily, @weekly, @monthly and @yearly.  As in cron, when both day
fields are restricted a day matching either one counts.  Times are read in
the schedule's own time zone, so "03:00" stays 03:00 across DST changes (a
time skipped by the clock change is skipped).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

ALIASES = {
    "@hourly": "0 * * * *",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@weekly": "0 0 * * 0",
    "@monthly": "0 0 1 * *",
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
}
MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]
# How far ahead to look for the next time; "0 0 29 2 1" can take years.
HORIZON_DAYS = 366 * 8


class CronError(ValueError):
    pass


def _field(text: str, low: int, high: int, names=None, what="") -> set[int]:
    values: set[int] = set()

    def number(token):
        token = token.lower()
        if names and token in names:
            return names.index(token) + (1 if what == "month" else 0)
        if not token.isdigit():
            raise CronError(f"{token!r} is not a valid {what}.")
        return int(token)

    for part in text.split(","):
        if not part:
            raise CronError(f"Empty item in the {what} field.")
        step = 1
        if "/" in part:
            part, step_text = part.split("/", 1)
            if not step_text.isdigit() or int(step_text) == 0:
                raise CronError(f"Bad step in the {what} field.")
            step = int(step_text)
        if part == "*":
            start, end = low, high
        elif "-" in part:
            first, last = part.split("-", 1)
            start, end = number(first), number(last)
        else:
            start = number(part)
            end = high if step > 1 else start
        if not (low <= start <= high and low <= end <= high):
            raise CronError(f"The {what} field allows {low}-{high}.")
        if start > end:
            raise CronError(f"The range {start}-{end} in the {what} field runs backwards.")
        values.update(range(start, end + 1, step))
    return values


@dataclass(frozen=True)
class Cron:
    minutes: frozenset
    hours: frozenset
    days: frozenset
    months: frozenset
    weekdays: frozenset  # 0 = Sunday
    any_day: bool
    any_weekday: bool

    @classmethod
    def parse(cls, expression: str) -> "Cron":
        text = ALIASES.get((expression or "").strip().lower(), (expression or "").strip())
        fields = text.split()
        if len(fields) != 5:
            raise CronError("Five fields: minute hour day-of-month month day-of-week, e.g. 0 3 * * mon-fri.")
        minute, hour, day, month, weekday = fields
        weekdays = _field(weekday, 0, 7, DAYS, "day of week")
        if 7 in weekdays:
            weekdays = (weekdays - {7}) | {0}
        return cls(
            minutes=frozenset(_field(minute, 0, 59, what="minute")),
            hours=frozenset(_field(hour, 0, 23, what="hour")),
            days=frozenset(_field(day, 1, 31, what="day of month")),
            months=frozenset(_field(month, 1, 12, MONTHS, "month")),
            weekdays=frozenset(weekdays),
            any_day=day == "*" or day.startswith("*/"),
            any_weekday=weekday == "*" or weekday.startswith("*/"),
        )

    def day_matches(self, day: date) -> bool:
        if day.month not in self.months:
            return False
        in_month = day.day in self.days
        in_week = (day.isoweekday() % 7) in self.weekdays
        if self.any_day and self.any_weekday:
            return True
        if self.any_day:
            return in_week
        if self.any_weekday:
            return in_month
        return in_month or in_week

    def next_after(self, moment: datetime, zone: str) -> datetime | None:
        """The first time strictly after moment, as an aware datetime; None if never."""
        tz = ZoneInfo(zone)
        local = moment.astimezone(tz)
        start = local.replace(second=0, microsecond=0) + timedelta(minutes=1)
        day = start.date()
        for _ in range(HORIZON_DAYS):
            if self.day_matches(day):
                for hour in sorted(self.hours):
                    for minute in sorted(self.minutes):
                        candidate = datetime.combine(day, time(hour, minute), tzinfo=tz)
                        if candidate < start:
                            continue
                        # A wall-clock time that the DST change skips does not exist.
                        if candidate.astimezone(ZoneInfo("UTC")).astimezone(tz).replace(tzinfo=None) != candidate.replace(tzinfo=None):
                            continue
                        return candidate
            day += timedelta(days=1)
        return None


def validate(expression: str) -> str:
    """The expression, tidied; raises CronError with a readable reason."""
    Cron.parse(expression)
    return " ".join((expression or "").split())
