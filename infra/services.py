# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Starting OpenTofu runs."""
from runs.models import Job

from .models import TofuProject


def start_plan(project: TofuProject, user, destroy: bool = False) -> Job:
    """Create a plan job; the caller dispatches it."""
    job = Job.objects.create(
        kind=Job.KIND_TOFU_PLAN,
        tofu_project=project,
        tofu_destroy=destroy,
        playbook_name=f"{project.name}: {'destroy plan' if destroy else 'plan'}",
        playbook_yaml="",
        created_by=user,
    )
    # The project's group as the target makes the job visible, cancellable and
    # appliable by exactly the people with a role on that group.
    job.target_groups.set([project.host_group])
    return job
