# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Laying a workflow out as a picture: steps in columns by depth, arrows between.

Drawn on the server as inline SVG, so it needs no script and follows the
theme's colours.
"""
from __future__ import annotations

from .models import Edge

W, H = 190, 52
GAP_X, GAP_Y, PAD = 70, 22, 12
LANE = 16  # spacing of the arrows that run below the boxes


def layout(steps, edges, nodes=None) -> dict:
    """steps: Step rows; edges: Edge rows; nodes: {step_id: Node} for a run."""
    steps = list(steps)
    edges = list(edges)
    parents = {s.pk: [] for s in steps}
    for edge in edges:
        parents.setdefault(edge.child_id, []).append(edge.parent_id)
    depth = {}

    def level(step_id, seen=()):
        if step_id in depth:
            return depth[step_id]
        if step_id in seen:  # a cycle should not exist; do not hang on one
            return 0
        found = max((level(p, (*seen, step_id)) + 1 for p in parents.get(step_id, [])), default=0)
        depth[step_id] = found
        return found

    columns: dict[int, list] = {}
    for step in steps:
        columns.setdefault(level(step.pk), []).append(step)
    boxes, where = [], {}
    for col, members in sorted(columns.items()):
        for row, step in enumerate(members):
            x, y = PAD + col * (W + GAP_X), PAD + row * (H + GAP_Y)
            where[step.pk] = (x, y)
            node = (nodes or {}).get(step.pk)
            boxes.append({
                "step": step, "x": x, "y": y, "w": W, "h": H,
                "node": node, "badge": node.badge if node else "",
                "kind": step.get_kind_display(),
            })
    width = PAD * 2 + (max(columns, default=0) + 1) * (W + GAP_X) - GAP_X
    height = PAD * 2 + max((len(m) for m in columns.values()), default=1) * (H + GAP_Y) - GAP_Y
    lines, lane = [], 0
    for edge in edges:
        if edge.parent_id not in where or edge.child_id not in where:
            continue
        (x1, y1), (x2, y2) = where[edge.parent_id], where[edge.child_id]
        x1, y1, y2 = x1 + W, y1 + H / 2, y2 + H / 2
        if depth[edge.child_id] - depth[edge.parent_id] > 1:
            # Jumping columns: go round below the boxes, not under one of them.
            below = height - PAD + LANE * (lane + 1)
            lane += 1
            d = (f"M{x1},{y1} C{x1 + 30},{y1} {x1 + 30},{below} {x1 + 55},{below} "
                 f"L{x2 - 55},{below} C{x2 - 30},{below} {x2 - 30},{y2} {x2 - 4},{y2}")
        else:
            mid = (x1 + x2) / 2
            d = f"M{x1},{y1} C{mid},{y1} {mid},{y2} {x2 - 4},{y2}"
        lines.append({"d": d, "condition": edge.condition,
                      "label": dict(Edge.CONDITION_CHOICES)[edge.condition]})
    height += LANE * lane
    return {"width": width, "height": height, "boxes": boxes, "lines": lines}
