# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
import tempfile
from pathlib import Path

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.decorators.http import require_POST
from django.views.generic import (
    CreateView,
    DeleteView,
    DetailView,
    ListView,
    UpdateView,
)
from django.utils.translation import gettext as _

from access import policy

from . import facts, probe, provisioning, services
from .forms import (
    ConnectionProbeForm,
    CredentialForm,
    HostForm,
    HostGroupForm,
    KeyProvisionForm,
)
from .models import Credential, Host, HostFacts, HostGroup


class Flash:
    """Mixin that reports what happened after a successful form submit."""

    success_message = ""

    def form_valid(self, form):
        response = super().form_valid(form)
        if self.success_message:
            messages.success(self.request, self.success_message.format(obj=self.object))
        return response


class UserForm:
    """Hands the signed-in user to forms that scope their choices by it."""

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs


class Scoped(LoginRequiredMixin):
    """Detail-style views over hosts or groups, gated on the user's role.

    Objects the user cannot see at all are a 404, so their existence does not
    leak; ones they can see but not act on are a 403.
    """

    required_role = policy.VIEWER

    @property
    def access(self):
        return policy.for_user(self.request.user)

    def get_queryset(self):
        if self.model is Host:
            return self.access.hosts()
        return self.access.groups()

    def get_object(self, queryset=None):
        obj = super().get_object(queryset)
        if self.model is Host:
            self.access.require_host(obj, self.required_role)
        else:
            self.access.require_group(obj, self.required_role)
        return obj


class ManagesInventory(LoginRequiredMixin):
    """Creating hosts or groups takes admin rights on at least one group."""

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and not policy.for_user(request.user).manages_inventory:
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)


def _host_for(request, pk, role):
    host = get_object_or_404(
        policy.for_user(request.user).hosts().select_related("credential"), pk=pk
    )
    policy.for_user(request.user).require_host(host, role)
    return host


# -- hosts ------------------------------------------------------------------


class HostList(LoginRequiredMixin, ListView):
    model = Host
    template_name = "inventory/host_list.html"
    context_object_name = "hosts"
    paginate_by = 50

    def get_queryset(self):
        qs = (
            policy.for_user(self.request.user)
            .hosts()
            .select_related("credential", "managed_key", "facts")
            .defer("facts__facts")
            .prefetch_related("groups")
        )
        query = self.request.GET.get("q", "").strip()
        self.search_errors = []
        if query:
            search = facts.parse(query)
            self.search_errors = search.errors
            qs = qs.filter(search.filter)
        group = self.request.GET.get("group")
        if group:
            qs = qs.filter(groups__pk=group)
        return qs.distinct()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["groups"] = policy.for_user(self.request.user).groups().annotate(
            n=Count("hosts")
        )
        context["q"] = self.request.GET.get("q", "")
        context["active_group"] = self.request.GET.get("group", "")
        context["search_errors"] = self.search_errors
        context["search_help"] = facts.help_text()
        return context


class HostDetail(Scoped, DetailView):
    model = Host
    template_name = "inventory/host_detail.html"
    context_object_name = "host"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        from .history import timeline

        context["history"] = timeline(self.object, self.request.user, limit=12)
        context["key"] = getattr(self.object, "managed_key", None)
        context.update(_facts_context(self.object))
        return context


def _facts_context(host):
    found = HostFacts.objects.filter(host=host).select_related("job").first()
    if found is None:
        return {"host_facts": None}
    return {
        "host_facts": found,
        "disks": facts.disks(found.facts),
        "interfaces": facts.interfaces(found.facts),
        "uptime": found.facts.get("ansible_uptime_seconds"),
    }


@login_required
def host_facts(request, pk):
    """Everything Ansible reported about the host, with a filter."""
    host = _host_for(request, pk, policy.VIEWER)
    context = {"host": host, **_facts_context(host)}
    if context["host_facts"]:
        context["devices"] = facts.devices(context["host_facts"].facts)
        context["rows"] = facts.flatten(context["host_facts"].facts)
    return render(request, "inventory/host_facts.html", context)


@login_required
@require_POST
def host_gather_facts(request, pk):
    host = _host_for(request, pk, policy.OPERATOR)
    if not host.enabled:
        messages.error(request, _('%(name)s is disabled; Loona does not connect to it.') % {"name": host.name})
        return redirect(host)
    return redirect(facts.start(request.user, hosts=[host]))


@login_required
@require_POST
def group_gather_facts(request, pk):
    group = get_object_or_404(policy.for_user(request.user).groups(), pk=pk)
    policy.for_user(request.user).require_group(group, policy.OPERATOR)
    if not any(h.enabled for h in group.all_hosts()):
        messages.error(request, _('%(name)s has no enabled hosts to gather facts from.') % {"name": group.name})
        return redirect(group)
    return redirect(facts.start(request.user, groups=[group]))


@login_required
def host_history(request, pk):
    from .history import timeline

    host = _host_for(request, pk, policy.VIEWER)
    return render(
        request,
        "inventory/host_history.html",
        {"host": host, "history": timeline(host, request.user, limit=300)},
    )


class HostCreate(ManagesInventory, UserForm, Flash, CreateView):
    model = Host
    form_class = HostForm
    template_name = "inventory/host_form.html"
    success_message = "Host {obj} created."

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["probe"] = ConnectionProbeForm()
        return context


class HostUpdate(Scoped, UserForm, Flash, UpdateView):
    model = Host
    required_role = policy.ADMIN
    form_class = HostForm
    template_name = "inventory/host_form.html"
    success_message = "Host {obj} saved."

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["probe"] = ConnectionProbeForm()
        return context


class HostDelete(Scoped, DeleteView):
    """Delete a host, offering to take Loona's key off it first."""

    model = Host
    required_role = policy.ADMIN
    template_name = "inventory/host_confirm_delete.html"
    success_url = reverse_lazy("host_list")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["key"] = getattr(self.object, "managed_key", None)
        return context

    def form_valid(self, form):
        host = self.object
        key = getattr(host, "managed_key", None)
        if key and key.is_installed and self.request.POST.get("revoke_key"):
            job = provisioning.start_key_revoke(
                host, key, user=self.request.user, delete_host=True
            )
            messages.info(
                self.request,
                _("Removing Loona's key from %(name)s. The host is deleted as soon as that succeeds.") % {"name": host.name},
            )
            return redirect(job)
        if key and key.is_installed:
            messages.warning(
                self.request,
                _("%(name)s is gone, but Loona's key is still in %(username)s's authorized_keys on that machine. Remove it by hand: %(fingerprint)s") % {"name": host.name, "username": key.username, "fingerprint": key.fingerprint},
            )
        return super().form_valid(form)


# -- connection checks ------------------------------------------------------


@login_required
@require_POST
def host_probe(request):
    """Try the connection described by the form on screen and report back.

    Answers into the page it was called from - the new-host form included, where
    there is nothing saved yet - so checking an address never costs you the form
    you were filling in.
    """
    form = ConnectionProbeForm(request.POST, user=request.user)
    host = None
    host_pk = request.POST.get("host")
    if host_pk:
        host = _host_for(request, host_pk, policy.ADMIN)
    elif not policy.for_user(request.user).manages_inventory:
        raise PermissionDenied

    via = host.reached_via if host is not None else ""
    if not form.is_valid():
        result = probe.ProbeResult(
            "fail", _("Check the address and port first."), _first_error(form)
        )
    elif via:
        # The check runs inside this request, from Loona - which is exactly
        # where this host cannot be reached from.
        result = probe.ProbeResult(
            "warn",
            _('Not checked: this host is reached through executor %(via)s.') % {"via": via},
            _("Loona itself cannot see it. Use Gather facts instead - that runs on the executor."),
        )
    elif _sends_login_elsewhere(form, host, request.user):
        result = probe.ProbeResult(
            "fail",
            _("Not checked: this host logs in with %(credential)s, which is not shared with you.") % {
                "credential": host.credential},
            _("Type a login and password to try the new address with those instead."),
        )
    else:
        result = _run_probe(form, host)
    return render(request, "inventory/_probe_result.html", {"result": result})


def _sends_login_elsewhere(form, host, user) -> bool:
    """Would the check hand the host's stored login to an address other than
    its own, for someone who may not use that login themselves?"""
    from .forms import may_use_credential

    if host is None or form.cleaned_data["password"]:
        # A typed password replaces everything stored (apply_connection_override).
        return False
    address = form.target_address()
    port = form.cleaned_data["port"]
    moved = (address and address != host.ansible_host) or (port and port != host.port)
    return bool(moved) and not may_use_credential(policy.for_user(user), host.credential)


def _first_error(form):
    for field, errors in form.errors.items():
        return f"{field}: {errors[0]}"
    return ""


def _run_probe(form, host):
    address = form.target_address() or (host.ansible_host if host else "")
    if not address:
        return probe.ProbeResult(
            "fail", _("Fill in the name or address first."), _("There is nothing to connect to yet.")
        )
    password = form.cleaned_data["password"]
    if password and not provisioning.sshpass_available():
        return probe.ProbeResult("fail", _("Password logins need sshpass."), SSHPASS_HINT)

    def build(keys_dir):
        return _probe_variables(form, host, keys_dir)

    # Nothing to authenticate with is worth saying outright rather than spending
    # a timeout on.
    with tempfile.TemporaryDirectory() as tmp:
        preview = _probe_variables(form, host, Path(tmp))
    if not _has_authentication(preview):
        return probe.ProbeResult(
            "fail",
            _("Loona has no way to log in yet."),
            _("Type a password, or pick a credential that carries a private key."),
        )
    # The pinned key belongs to the saved address; one typed in may well be
    # another machine, so it is checked without a pin.
    pinned = ""
    if host is not None and (address, form.cleaned_data["port"] or host.port) == (host.ansible_host, host.port):
        pinned = host.ssh_host_keys
    return probe.check_connection(build, label=address, host_keys=pinned)


def _probe_variables(form, host, keys_dir):
    """Connection variables for the check, from a host that may not exist yet."""
    username = form.cleaned_data["username"]
    password = form.cleaned_data["password"]

    if host is not None:
        variables = services.host_vars(host, keys_dir)
        # On the edit form the point is usually to try an address that has not
        # been saved yet, so what is on screen wins over what is stored.
        if form.target_address():
            variables["ansible_host"] = form.target_address()
        if form.cleaned_data["port"]:
            variables["ansible_port"] = form.cleaned_data["port"]
    else:
        variables = {
            "ansible_host": form.target_address(),
            "ansible_port": form.cleaned_data["port"] or 22,
        }
        variables.update(services.credential_vars(form.cleaned_data["credential"], keys_dir))

    if password:
        # A typed password replaces the stored authentication outright.
        variables = services.apply_connection_override(
            variables,
            {
                "ansible_user": username or variables.get("ansible_user") or "root",
                "ansible_password": password,
            },
        )
    elif username:
        variables["ansible_user"] = username
    return variables


def _has_authentication(variables) -> bool:
    if variables.get("ansible_connection") == "local":
        return True
    return bool(
        variables.get("ansible_password") or variables.get("ansible_ssh_private_key_file")
    )


# -- per-host SSH keys ------------------------------------------------------

SSHPASS_HINT = (
    "The sshpass program is not installed on the Loona server, and Ansible needs "
    "it to log in with a password. Install it, or give this host a credential "
    "that carries a private key."
)


@login_required
def host_key(request, pk):
    """Everything about the key Loona uses to reach one host."""
    host = _host_for(request, pk, policy.ADMIN)
    return render(request, "inventory/host_key.html", _key_context(host))


def _key_context(host, form=None):
    key = getattr(host, "managed_key", None)
    return {
        "host": host,
        "key": key,
        "form": form or KeyProvisionForm(
            initial={"username": key.username if key else _suggested_login(host)},
            host=host,
        ),
        "probe": ConnectionProbeForm(),
        "pending_job": _pending_key_job(host),
        "key_jobs": _key_jobs(host),
        "sshpass_missing": not provisioning.sshpass_available(),
    }


def _suggested_login(host):
    return host.credential.username if host.credential else "root"


def _key_jobs(host):
    """This host's key management runs, newest first."""
    from runs.models import Job

    return host.jobs.exclude(kind__in=(Job.KIND_PLAYBOOK, Job.KIND_FACTS))[:10]


def _pending_key_job(host):
    """The key run still in flight, if any - what the panel polls on."""
    from runs.models import Job

    return (
        host.jobs.filter(kind__in=Job.SYSTEM_KINDS)
        .exclude(status__in=Job.FINAL_STATUSES)
        .first()
    )


def _key_panel(request, host, form=None):
    """The key panel on its own, for htmx to swap in place."""
    context = _key_context(host, form)
    # The runs list lives in the other column and rides along out of band.
    context["oob"] = True
    return render(request, "inventory/_key_panel.html", context)


@login_required
def host_key_status(request, pk):
    """Poll target: the key panel as it stands right now."""
    host = _host_for(request, pk, policy.ADMIN)
    return _key_panel(request, host)


@login_required
@require_POST
def host_key_provision(request, pk):
    """Generate a key for this host and push it, without leaving the page."""
    host = _host_for(request, pk, policy.ADMIN)
    form = KeyProvisionForm(request.POST, host=host)
    if not form.is_valid():
        return _key_panel(request, host, form)

    username = form.cleaned_data["username"]
    password = form.cleaned_data["password"]
    if password and not provisioning.sshpass_available():
        form.add_error(None, SSHPASS_HINT)
        return _key_panel(request, host, form)

    override = provisioning.password_override(username, password) if password else None
    key = provisioning.ensure_keypair(host, username)
    provisioning.start_key_install(host, key, user=request.user, override=override)
    host.refresh_from_db()
    return _key_panel(request, host)


@login_required
@require_POST
def host_key_revoke(request, pk):
    """Take Loona's key off the server but keep the host."""
    host = _host_for(request, pk, policy.ADMIN)
    key = getattr(host, "managed_key", None)
    if key is not None:
        if key.is_installed:
            provisioning.start_key_revoke(host, key, user=request.user)
        else:
            key.delete()
    host.refresh_from_db()
    return _key_panel(request, host)


@login_required
@require_POST
def host_key_forget(request, pk):
    """Drop Loona's copy of a key it cannot remove from the server.

    The escape hatch for a machine that is already gone: the record here goes
    away, and the fingerprint is reported so the key can be pulled by hand.
    """
    host = _host_for(request, pk, policy.ADMIN)
    key = getattr(host, "managed_key", None)
    if key:
        fingerprint, username = key.fingerprint, key.username
        key.delete()
        messages.warning(
            request,
            _("Forgot Loona's key for %(name)s. It may still be in %(username)s's authorized_keys there - remove %(fingerprint)s by hand.") % {"name": host.name, "username": username, "fingerprint": fingerprint},
        )
    host.refresh_from_db()
    return _key_panel(request, host)


@login_required
@require_POST
def host_forget_host_key(request, pk):
    """Unpin the server's SSH host key, for a machine that was rebuilt."""
    host = _host_for(request, pk, policy.ADMIN)
    from .forms import may_use_credential

    if not may_use_credential(policy.for_user(request.user), host.credential):
        # Whatever answers next gets the credential's password.
        messages.error(request, _("This host logs in with %(credential)s, which is not shared with you; "
                                  "ask its owner to forget the key.") % {"credential": host.credential})
        return redirect(host)
    host.ssh_host_keys = ""
    host.ssh_host_keys_pinned_at = None
    host.save(update_fields=["ssh_host_keys", "ssh_host_keys_pinned_at"])
    messages.warning(
        request,
        _('Forgot the SSH host key of %(name)s. Loona trusts whatever answers at %(ansible_host)s:%(port)s next time and pins that.') % {"name": host.name, "ansible_host": host.ansible_host, "port": host.port},
    )
    return redirect(host)


# -- groups -----------------------------------------------------------------


class GroupList(LoginRequiredMixin, ListView):
    model = HostGroup
    template_name = "inventory/group_list.html"
    context_object_name = "groups"

    def get_queryset(self):
        return policy.for_user(self.request.user).groups().annotate(n=Count("hosts")).prefetch_related("parents")


class GroupDetail(Scoped, DetailView):
    model = HostGroup
    template_name = "inventory/group_detail.html"
    context_object_name = "group"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["effective_hosts"] = self.object.all_hosts()
        context["grants"] = self.object.grants.select_related("team")
        from access import approvals
        from access.models import MaintenanceWindow

        above = self.object.ancestor_ids()
        windows = list(MaintenanceWindow.objects.filter(host_group_id__in=above).select_related("host_group"))
        context["windows"] = windows
        context["window_closed"] = approvals.outside_window(above) if windows else None
        return context


class GroupCreate(ManagesInventory, UserForm, Flash, CreateView):
    model = HostGroup
    form_class = HostGroupForm
    template_name = "inventory/group_form.html"
    success_message = "Group {obj} created."


class GroupUpdate(Scoped, UserForm, Flash, UpdateView):
    model = HostGroup
    required_role = policy.ADMIN
    form_class = HostGroupForm
    template_name = "inventory/group_form.html"
    success_message = "Group {obj} saved."


class GroupDelete(Scoped, DeleteView):
    model = HostGroup
    required_role = policy.ADMIN
    template_name = "core/confirm_delete.html"
    success_url = reverse_lazy("group_list")


# -- credentials ------------------------------------------------------------


class ManagesCredentials(PermissionRequiredMixin):
    permission_required = "inventory.change_credential"


class CredentialList(ManagesCredentials, ListView):
    model = Credential
    template_name = "inventory/credential_list.html"
    context_object_name = "credentials"

    def get_queryset(self):
        return Credential.objects.annotate(n=Count("hosts"))


class CredentialCreate(ManagesCredentials, Flash, CreateView):
    model = Credential
    form_class = CredentialForm
    template_name = "inventory/credential_form.html"
    success_url = reverse_lazy("credential_list")
    success_message = "Credential {obj} created."


class CredentialUpdate(ManagesCredentials, Flash, UpdateView):
    model = Credential
    form_class = CredentialForm
    template_name = "inventory/credential_form.html"
    success_url = reverse_lazy("credential_list")
    success_message = "Credential {obj} saved."


class CredentialDelete(ManagesCredentials, DeleteView):
    model = Credential
    template_name = "core/confirm_delete.html"
    success_url = reverse_lazy("credential_list")
