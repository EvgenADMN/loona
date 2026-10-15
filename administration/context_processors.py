# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from . import system


def instance(request):
    return {"LOONA_INSTANCE": system.get().instance_name}
