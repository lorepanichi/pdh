#
# This file is part of the pdh (https://github.com/mbovo/pdh).
# Copyright (c) 2020-2025 Manuel Bovo.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
import importlib.metadata
import sys

import click

from .config import load_and_validate, setup_config
from .core import PDH
from .output import VALID_OUTPUTS


@click.group(help="PDH - PagerDuty for Humans")
def main():
    pass


@main.command(help="Create default configuration file")
@click.option("-c", "--config", default="~/.config/pdh.yaml", help="Configuration file location (default: ~/.config/pdh.yaml)")
def config(config):
    setup_config(config)


@main.command(help="Print cloud tools version and exit")
def version():
    click.echo(f"v{importlib.metadata.version('pdh')}")


@main.group(help="Operate on Users")
@click.option("-c", "--config", envvar="PDH_CONFIG", default="~/.config/pdh.yaml", help="Configuration file location (default: ~/.config/pdh.yaml)")
@click.pass_context
def user(ctx, config):
    cfg = load_and_validate(config)
    ctx.ensure_object(dict)
    ctx.obj = cfg


@user.command(help="List users", name="ls")
@click.pass_context
@click.option("-o", "--output", "output", help="output format", required=False, type=click.Choice(VALID_OUTPUTS), default="table")
@click.option("-f", "--fields", "fields", help="Filter fields", required=False, type=str, default=None)
def user_list(ctx, output, fields):
    if not PDH.list_user(ctx.obj, output, fields):
        sys.exit(1)


@user.command(help="Retrieve an user by name or ID", name="get")
@click.pass_context
@click.argument("user")
@click.option("-o", "--output", "output", help="output format", required=False, type=click.Choice(VALID_OUTPUTS), default="table")
@click.option("-f", "--fields", "fields", help="Filter fields", required=False, type=str, default=None)
def user_get(ctx, user, output, fields):
    if not PDH.get_user(ctx.obj, user, output, fields):
        sys.exit(1)


@main.group(help="Operate on Incidents")
@click.option("-c", "--config", envvar="PDH_CONFIG", default="~/.config/pdh.yaml", help="Configuration file location (default: ~/.config/pdh.yaml)")
@click.pass_context
def inc(ctx, config):
    cfg = load_and_validate(config)
    ctx.ensure_object(dict)
    ctx.obj = cfg


@inc.command(help="Acknowledge specific incidents IDs")
@click.pass_context
@click.argument("incidentids", nargs=-1)
def ack(ctx, incidentids):
    PDH.ack(ctx.obj, incidentids)


@inc.command(help="Resolve specific incidents IDs")
@click.pass_context
@click.argument("incidentids", nargs=-1)
def resolve(ctx, incidentids):
    PDH.resolve(ctx.obj, incidentids)


@inc.command(help="Snooze the incident(s) for the specified duration in seconds")
@click.pass_context
@click.option("-d", "--duration", required=False, default=14400, help="Duration of snooze in seconds")
@click.argument("incidentids", nargs=-1)
def snooze(ctx, incidentids, duration):
    PDH.snooze(ctx.obj, incidentids, duration)


@inc.command(help="Re-assign the incident(s) to the specified user")
@click.pass_context
@click.option("-u", "--user", required=True, help="User name or email to assign to (fuzzy find!)")
@click.argument("incident", nargs=-1)
def reassign(ctx, incident, user):
    PDH.reassign(ctx.obj, incident, user)


@inc.command(help="List incidents", name="ls")
@click.pass_context
@click.option("-e", "--everything", help="List all incidents not only assigned to me", is_flag=True, default=False)
@click.option("-u", "--user", default=None, help="Filter only incidents assigned to this user ID")
@click.option("-n", "--new", is_flag=True, default=False, help="Filter only newly triggered incident")
@click.option("-a", "--ack", is_flag=True, default=False, help="Acknowledge incident listed here")
@click.option("-s", "--snooze", is_flag=True, default=False, help="Snooze for 4 hours incident listed here")
@click.option("-r", "--resolve", is_flag=True, default=False, help="Resolve the incident listed here")
@click.option("-h", "--high", is_flag=True, default=False, help="List only HIGH priority incidents")
@click.option("-l", "--low", is_flag=True, default=False, help="List only LOW priority incidents")
@click.option("-w", "--watch", is_flag=True, default=False, help="Continuously print the list")
@click.option("-t", "--timeout", default=5, help="Watch every x seconds (work only if -w is flagged)")
@click.option("--rules", is_flag=True, default=False, help="apply rules from a path (see --rules--path")
@click.option("--rules-path", required=False, default="~/.config/pdh_rules", help="Apply all executable find in this path")
@click.option("-R", "--regexp", help="regexp to filter incidents", default=None)
@click.option("--excluded-regexp", "excluded_filter_re", help="Exclude incident of these titles (regexp)", default=None)
@click.option("-o", "--output", "output", help="output format", required=False, type=click.Choice(VALID_OUTPUTS), default="table")
@click.option("-f", "--fields", "fields", required=False, help="Fields to filter and output", default=None)
@click.option("--alerts", "alerts", required=False, help="Show alerts associated to each incidents", is_flag=True, default=False)
@click.option("--alert-fields", "alert_fields", required=False, help="Show these alert fields only, comma separated", default=None)
@click.option("-S", "--service-re", "service_re", required=False, help="Show only incidents for this service (regexp)", default=None)
@click.option("--excluded-service-re", "excluded_service_re", required=False, help="Exclude incident of these services (regexp)", default=None)
@click.option("--sort", "sort_by", required=False, help="Sort by field name", default=None)
@click.option("--reverse", "reverse_sort", required=False, help="Reverse the sort", is_flag=True, default=False)
@click.option("-T", "--teams", "teams", required=False, help="Filter only incidents assigned to this team IDs", default=None)
def list_incidents(ctx, **kwargs):
    if not PDH.list_incidents(ctx.obj, **kwargs):
        sys.exit(1)


@main.group(help="Operate on Services", name="svc")
@click.option("-c", "--config", envvar="PDH_CONFIG", default="~/.config/pdh.yaml", help="Configuration file location (default: ~/.config/pdh.yaml)")
@click.pass_context
def svc(ctx, config):
    cfg = load_and_validate(config)
    ctx.ensure_object(dict)
    ctx.obj = cfg


@svc.command(help="List services", name="ls")
@click.option("-o", "--output", "output", help="output format", required=False, type=click.Choice(VALID_OUTPUTS), default="table")
@click.option("-f", "--fields", "fields", required=False, help="Fields to filter and output", default=None)
@click.option("--sort", "sort_by", required=False, help="Sort by field name", default=None)
@click.option("--reverse", "reverse_sort", required=False, help="Reverse the sort", is_flag=True, default=False)
@click.option("-s", "--status", "status", required=False, help="Filter for service status", default="active,warning,critical")
@click.pass_context
def list_services(ctx, output, fields, sort_by, reverse_sort, status):
    if not PDH.list_services(ctx.obj, output, fields, sort_by, reverse_sort, status):
        sys.exit(1)


@main.group(help="Operate on Teams", name="teams")
@click.option("-c", "--config", envvar="PDH_CONFIG", default="~/.config/pdh.yaml", help="Configuration file location (default: ~/.config/pdh.yaml)")
@click.pass_context
def teams(ctx, config):
    cfg = load_and_validate(config)
    ctx.ensure_object(dict)
    ctx.obj = cfg


@teams.command(help="List teams where current user belongs", name="mine")
@click.option("-o", "--output", "output", help="output format", required=False, type=click.Choice(VALID_OUTPUTS), default="table")
@click.option("-f", "--fields", "fields", required=False, help="Fields to filter and output", default=None)
@click.pass_context
def teams_mine(ctx, output, fields) -> None:
    if not PDH.list_teams(ctx.obj, mine=True, output=output, fields=fields):
        sys.exit(1)


@teams.command(help="List teams in a pagerduty account", name="ls")
@click.option("-o", "--output", "output", help="output format", required=False, type=click.Choice(VALID_OUTPUTS), default="table")
@click.option("-f", "--fields", "fields", required=False, help="Fields to filter and output", default=None)
@click.pass_context
def teams_list(ctx, output, fields) -> None:
    if not PDH.list_teams(ctx.obj, mine=False, output=output, fields=fields):
        sys.exit(1)
