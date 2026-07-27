from __future__ import annotations

from datetime import date
from typing import Any

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views import View

from sbomify.apps.teams.permissions import GuestAccessBlockedMixin

# NOTE (issue #1172): FRONT-END-ONLY first pass. There is no Advisory model or
# service layer yet, so the list/detail are populated from the dummy projection
# below and neither the create form nor "post update" persists. When the backend
# lands, swap `_dummy_advisories()` for a service call and wire the POST handlers.
#
# Domain model (see conversation / wireframes):
#   Advisory (title, description, severity, type, vulnerability_id, created_at)
#     └─ Updates[]  — commit-like timeline. Each update has a `kind`:
#          identified / investigating / fix_in_progress / resolved / wont_fix
#          (status-setting) OR `update` (a note that does NOT change status).
#   The advisory's current status is derived from the latest status-setting
#   update; "Updated" is the timestamp of the latest update of any kind.

# Severity → badge variant (advisory-level, set at creation).
SEVERITY_VARIANTS = {
    "critical": "danger",
    "high": "warning",
    "medium": "info",
    "low": "secondary",
}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Update kinds. `sets_status` kinds move the advisory's status; "update" is a
# note-only entry that appears in the timeline without changing status.
UPDATE_KINDS: dict[str, dict[str, Any]] = {
    "identified": {
        "label": "Identified",
        "variant": "warning",
        "icon": "fas fa-circle-exclamation",
        "sets_status": True,
    },
    "investigating": {
        "label": "Investigating",
        "variant": "info",
        "icon": "fas fa-magnifying-glass",
        "sets_status": True,
    },
    "fix_in_progress": {"label": "Fix in progress", "variant": "accent", "icon": "fas fa-wrench", "sets_status": True},
    "resolved": {"label": "Resolved", "variant": "success", "icon": "fas fa-circle-check", "sets_status": True},
    "wont_fix": {"label": "Won't fix", "variant": "secondary", "icon": "fas fa-ban", "sets_status": True},
    "update": {"label": "Update", "variant": "secondary", "icon": "fas fa-comment", "sets_status": False},
}
NOTE_ONLY_KIND = "update"

# Derived from UPDATE_KINDS so there is one source of truth for the vocabulary.
STATUS_LABELS = {k: v["label"] for k, v in UPDATE_KINDS.items() if v["sets_status"]}
STATUS_VARIANTS = {k: v["variant"] for k, v in UPDATE_KINDS.items() if v["sets_status"]}
# Lifecycle order, used only for sorting the Status column.
STATUS_RANK = {"identified": 1, "investigating": 2, "fix_in_progress": 3, "resolved": 4, "wont_fix": 5}

TYPE_LABELS = {"cve": "CVE", "ghsa": "GHSA", "other": "Other"}


def _format_date(value: str) -> str:
    """ISO date string -> "19 Jul 2026" (no leading zero), or the raw value."""
    try:
        d = date.fromisoformat(value)
    except (ValueError, TypeError):
        return value or ""
    return f"{d.day} {d:%b %Y}"


def _dummy_advisories() -> list[dict[str, Any]]:
    """Placeholder advisories, each with a commit-like list of updates.

    Products are ``{"id", "name"}`` objects so the UI can link each chip to the
    product detail page. The ids are placeholders and will 404 until this is
    wired to real products (#1172).
    """
    return [
        {
            "id": "OSPN-2026-0034",
            "title": "Improper authentication in SAML assertion handling",
            "description": (
                "A flaw in SAML signature validation allows a crafted assertion to be accepted as valid, "
                "letting an attacker authenticate as another user."
            ),
            "severity": "critical",
            "type": "cve",
            "vulnerability_id": "CVE-2026-4471",
            "created_at": "2026-07-15",
            "products": [{"id": "prod-sign", "name": "Sign"}],
            "updates": [
                {"date": "2026-07-15", "kind": "identified", "note": "Vulnerability identified"},
                {"date": "2026-07-17", "kind": "investigating", "note": "Reproduced on 4.8.x; assessing scope"},
                {"date": "2026-07-19", "kind": "fix_in_progress", "note": "Patch in review, targeting 4.8.3"},
                {"date": "2026-07-20", "kind": "update", "note": "Advance notice sent to affected customers"},
            ],
        },
        {
            "id": "OSPN-2026-0033",
            "title": "Denial of service in provisioning endpoint",
            "description": "An unauthenticated request can exhaust worker threads on the provisioning endpoint.",
            "severity": "high",
            "type": "cve",
            "vulnerability_id": "CVE-2026-4102",
            "created_at": "2026-07-16",
            "products": [{"id": "prod-digipass", "name": "Digipass"}],
            "updates": [
                {"date": "2026-07-16", "kind": "identified", "note": "Vulnerability identified"},
                {"date": "2026-07-17", "kind": "investigating", "note": "Assessing exploitability"},
            ],
        },
        {
            "id": "OSPN-2026-0032",
            "title": "Weak default TLS ciphers",
            "description": "The default configuration enables cipher suites that no longer meet current guidance.",
            "severity": "medium",
            "type": "other",
            "vulnerability_id": "",
            "created_at": "2026-07-18",
            "products": [{"id": "prod-mobile-suite", "name": "Mobile Suite"}],
            "updates": [
                {"date": "2026-07-18", "kind": "identified", "note": "Vulnerability identified"},
            ],
        },
        {
            "id": "OSPN-2026-0028",
            "title": "Session fixation in admin console",
            "description": "The admin console does not rotate the session identifier on privilege change.",
            "severity": "medium",
            "type": "cve",
            "vulnerability_id": "CVE-2026-3980",
            "created_at": "2026-07-05",
            "products": [{"id": "prod-auth-server", "name": "Auth Server"}],
            "updates": [
                {"date": "2026-07-05", "kind": "identified", "note": "Vulnerability identified"},
                {"date": "2026-07-08", "kind": "fix_in_progress", "note": "Fix scheduled for 3.4.2"},
                {"date": "2026-07-11", "kind": "resolved", "note": "Fixed in 3.4.2"},
            ],
        },
        {
            "id": "OSPN-2026-0021",
            "title": "Verbose error responses leak stack traces",
            "description": "Unhandled errors return stack traces that reveal internal paths and library versions.",
            "severity": "low",
            "type": "cve",
            "vulnerability_id": "CVE-2026-3701",
            "created_at": "2026-06-25",
            "products": [{"id": "prod-sign", "name": "Sign"}],
            "updates": [
                {"date": "2026-06-25", "kind": "identified", "note": "Vulnerability identified"},
                {"date": "2026-06-30", "kind": "wont_fix", "note": "Low impact; endpoint deprecated in next major"},
            ],
        },
    ]


def _derive(advisory: dict[str, Any]) -> dict[str, Any]:
    """Attach the fields derived from the update timeline + display metadata."""
    updates = advisory.get("updates") or []

    # Current status = latest update whose kind sets a status (skip note-only).
    status = "identified"
    for update in updates:
        if update["kind"] != NOTE_ONLY_KIND:
            status = update["kind"]

    # "Updated" = latest update of any kind (a note-only update still bumps it).
    updated = max((u["date"] for u in updates), default=advisory.get("created_at", ""))

    advisory["status"] = status
    advisory["status_label"] = STATUS_LABELS.get(status, status)
    advisory["status_variant"] = STATUS_VARIANTS.get(status, "secondary")
    advisory["severity_variant"] = SEVERITY_VARIANTS.get(advisory["severity"], "secondary")
    advisory["severity_rank"] = SEVERITY_RANK.get(advisory["severity"], 0)
    advisory["status_rank"] = STATUS_RANK.get(status, 0)
    advisory["type_label"] = TYPE_LABELS.get(advisory.get("type", ""), "Other")
    advisory["updated"] = updated
    advisory["updates_count"] = len(updates)
    advisory["created_display"] = _format_date(advisory.get("created_at", ""))
    advisory["updated_display"] = _format_date(updated)
    return advisory


def _timeline(advisory: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the advisory's updates, newest first, with display metadata."""
    items: list[dict[str, Any]] = []
    for update in advisory.get("updates", []):
        meta = UPDATE_KINDS.get(update["kind"], UPDATE_KINDS[NOTE_ONLY_KIND])
        items.append(
            {
                **update,
                "label": meta["label"],
                "variant": meta["variant"],
                "icon": meta["icon"],
                "sets_status": meta["sets_status"],
                "date_display": _format_date(update["date"]),
            }
        )
    items.sort(key=lambda u: u["date"], reverse=True)
    return items


def _vex_candidates(advisory: dict[str, Any]) -> list[dict[str, Any]]:
    """VEX documents that could be linked to this advisory.

    A VEX is maintained per component (see ComponentVexDrift), so the candidates
    are the maintained VEX for workspace components that cover this advisory's
    vulnerability — affected products first. Dummy data for now (#1172); real
    linking would query the workspace's VEX artifacts / component VEX for the
    same CVE.
    """
    coverage = advisory.get("vulnerability_id") or advisory["id"]
    names = [product["name"] for product in advisory.get("products", [])]
    for extra in ("Auth Server", "Digipass", "Mobile Suite"):
        if extra not in names:
            names.append(extra)
    return [
        {
            "id": "vex-" + name.lower().replace(" ", "-"),
            "product": name,
            "format": "CycloneDX VEX",
            "coverage": coverage,
            "updated": advisory["updated_display"],
        }
        for name in names
    ]


def _get_advisory(advisory_id: str) -> dict[str, Any] | None:
    for advisory in _dummy_advisories():
        if advisory["id"] == advisory_id:
            return _derive(advisory)
    return None


def _get_advisories_context(request: HttpRequest) -> dict[str, Any]:
    """Build the context for the Security Advisories list views."""
    current_team = request.session.get("current_team") or {}
    has_crud_permissions = current_team.get("role") in ["owner", "admin"]

    advisories = [_derive(a) for a in _dummy_advisories()]

    open_count = sum(1 for a in advisories if a["status"] not in ("resolved", "wont_fix"))
    resolved_count = sum(1 for a in advisories if a["status"] == "resolved")

    return {
        "current_team": current_team,
        "has_crud_permissions": has_crud_permissions,
        "advisories": advisories,
        "advisories_count": len(advisories),
        "open_count": open_count,
        "resolved_count": resolved_count,
    }


class SecurityAdvisoriesDashboardView(GuestAccessBlockedMixin, LoginRequiredMixin, View):
    def get(self, request: HttpRequest) -> HttpResponse:
        context = _get_advisories_context(request)
        return render(request, "core/security_advisories_dashboard.html.j2", context)

    def post(self, request: HttpRequest) -> HttpResponse:
        # Front-end preview only — creation is not wired to a backend yet (#1172).
        # In the real flow this would create the Advisory and its first update
        # ("Vulnerability identified"); the user never sets status directly.
        title = request.POST.get("title", "").strip()
        messages.info(
            request,
            f'Preview only: "{title or "advisory"}" was not saved. '
            "Security advisories are not connected to the backend yet.",
        )
        return redirect("core:security_advisories_dashboard")


class SecurityAdvisoriesTableView(GuestAccessBlockedMixin, LoginRequiredMixin, View):
    """View for HTMX table refresh, mirroring ProductsTableView."""

    def get(self, request: HttpRequest) -> HttpResponse:
        context = _get_advisories_context(request)
        return render(request, "core/security_advisories_table.html.j2", context)


class SecurityAdvisoryDetailView(GuestAccessBlockedMixin, LoginRequiredMixin, View):
    """Drill-down page for a single advisory and its update timeline."""

    def get(self, request: HttpRequest, advisory_id: str) -> HttpResponse:
        advisory = _get_advisory(advisory_id)
        if advisory is None:
            raise Http404("Advisory not found")

        current_team = request.session.get("current_team") or {}
        context = {
            "current_team": current_team,
            "has_crud_permissions": current_team.get("role") in ["owner", "admin"],
            "advisory": advisory,
            "timeline": _timeline(advisory),
            "update_kinds": UPDATE_KINDS,
            "vex_candidates": _vex_candidates(advisory),
        }
        return render(request, "core/security_advisory_detail.html.j2", context)

    def post(self, request: HttpRequest, advisory_id: str) -> HttpResponse:
        # Front-end preview only — nothing persists yet (#1172).
        if _get_advisory(advisory_id) is None:
            raise Http404("Advisory not found")

        intent = request.POST.get("intent")
        if intent == "edit":
            title = request.POST.get("title", "").strip()
            messages.info(
                request,
                f'Preview only: changes to "{title or "advisory"}" were not saved. '
                "Security advisories are not connected to the backend yet.",
            )
        elif intent == "edit_update":
            messages.info(
                request,
                "Preview only: changes to the update were not saved. "
                "Security advisories are not connected to the backend yet.",
            )
        elif intent == "link_vex":
            count = len(request.POST.getlist("vex_ids"))
            noun = "VEX document" if count == 1 else "VEX documents"
            messages.info(
                request,
                f"Preview only: {count} {noun} were not linked. "
                "Security advisories are not connected to the backend yet.",
            )
        else:
            kind = request.POST.get("kind", NOTE_ONLY_KIND)
            label = UPDATE_KINDS.get(kind, UPDATE_KINDS[NOTE_ONLY_KIND])["label"]
            messages.info(
                request,
                f'Preview only: the "{label}" update was not saved. '
                "Security advisories are not connected to the backend yet.",
            )
        return redirect("core:security_advisory_detail", advisory_id=advisory_id)
