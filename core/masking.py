# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Keeping known secret values out of what a run writes to its log.

A playbook that prints a password - a debug task, a failed command echoing
its arguments, a task name with the variable in it - would otherwise store it
in the job log for anyone who may read the job.  ``no_log`` is the proper
answer and stays the author's job; this is the net under it.
"""
from __future__ import annotations

import json
import re

MASK = "********"
# Shorter values would blank out ordinary words and numbers all over the log.
MIN_LENGTH = 4
# The single lines of a multi-line secret (a key, a certificate) are worth
# masking on their own only when they are long enough to be distinctive.
MIN_LINE_LENGTH = 12


class Masker:
    def __init__(self, values=()):
        needles = set()
        # What it was made from, so a remote executor can make the same one.
        self.values = []
        for value in values:
            if not isinstance(value, str) or len(value) < MIN_LENGTH:
                continue
            if value not in self.values:
                self.values.append(value)
            needles.add(value)
            # As it appears inside JSON output: quotes, backslashes, newlines escaped.
            needles.add(json.dumps(value)[1:-1])
            if "\n" in value:
                needles.update(
                    line.strip() for line in value.splitlines() if len(line.strip()) >= MIN_LINE_LENGTH
                )
        needles = sorted((n for n in needles if len(n) >= MIN_LENGTH), key=len, reverse=True)
        self._pattern = re.compile("|".join(map(re.escape, needles))) if needles else None

    def __bool__(self):
        return self._pattern is not None

    def __call__(self, text):
        if self._pattern is None or not isinstance(text, str) or not text:
            return text
        return self._pattern.sub(MASK, text)

    def deep(self, value):
        """The same, through the strings of a JSON-like structure."""
        if self._pattern is None:
            return value
        if isinstance(value, str):
            return self(value)
        if isinstance(value, list):
            return [self.deep(v) for v in value]
        if isinstance(value, dict):
            return {self(k): self.deep(v) for k, v in value.items()}
        return value
