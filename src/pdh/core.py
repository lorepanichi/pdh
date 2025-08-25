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
import os
import re
import time
from datetime import timezone
from typing import List, Optional

from rich.console import Console

from . import Filters, Transformations
from .config import Config
from .filters import Filter
from .output import print, print_items
from .pd import DEFAULT_URGENCIES, STATUS_ACK, STATUS_RESOLVED, STATUS_TRIGGERED, URGENCY_HIGH, URGENCY_LOW, PagerDuty, UnauthorizedException


class PDH(object):
    @staticmethod
    def list_user(cfg: Config, output: str, fields: list | None = None) -> bool:
        try:
            if fields is None:
                fields = ["id", "name", "email", "time_zone", "role", "job_title", "teams"]

            if isinstance(fields, str):
                fields = fields.split(",")

            users = PagerDuty(cfg).users.list()

            if output == "raw":
                filtered = users
            else:
                t = {}
                for f in fields:
                    t[f] = Transformations.extract(f)
                if "teams" in fields:
                    t["teams"] = Transformations.extract_users_teams()
                filtered = Transformations.apply(users, t)

            print_items(filtered, output)
            return True
        except UnauthorizedException as e:
            print(f"[red]{e}[/red]")
            return False

    @staticmethod
    def get_user(cfg: Config, user: str, output: str, fields: list | None = None):
        try:
            u = PagerDuty(cfg).users
            users = u.search(user)
            if len(users) == 0:
                users = u.search(user, "id")

            if fields is None:
                fields = ["id", "name", "email", "time_zone", "role", "job_title"]

            if isinstance(fields, str):
                fields = fields.split(",")

            # Prepare to filter and transform
            if output == "raw":
                filtered = users
            else:
                transformations = {}
                for t in fields:
                    transformations[t] = Transformations.extract(t)
                transformations["teams"] = Transformations.extract_users_teams()

                filtered = Transformations.apply(users, transformations)

            print_items(filtered, output)
            return True
        except UnauthorizedException as e:
            print(f"[red]{e}[/red]")
            return False

    @staticmethod
    def list_teams(cfg: Config, mine: bool = True, output="table", fields=None) -> bool:
        try:
            pd = PagerDuty(cfg)
            if mine:
                teams = dict(pd.me)["teams"] if "teams" in pd.me else []
            else:
                teams = pd.teams.list()

            # set fields that will be displayed
            if type(fields) is str:
                fields = fields.lower().strip().split(",")
            else:
                fields = ["id", "summary", "html_url"]

            def plain_print_f(i):
                s = ""
                for f in fields:
                    s += f"{i[f]}\t"
                print(s)

            if output != "raw":
                transformations = dict()

                for f in fields:
                    transformations[f] = Transformations.extract(f)

                filtered = Transformations.apply(teams, transformations)
            else:
                filtered = teams

            print_items(filtered, output, plain_print_f=plain_print_f)
            return True
        except UnauthorizedException as e:
            print(f"[red]{e}[/red]")
            return False

    @staticmethod
    def list_services(
        cfg: Config, output: str = "table", fields: List | None = None, sort_by: str | None = None, reverse_sort: bool = False, status: str = "active,warning,critical"
    ) -> bool:
        try:
            pd = PagerDuty(cfg)
            svcs = pd.services.list()

            svcs = Filter.apply(svcs, [Filter.inList("status", status.split(","))])

            # set fields that will be displayed
            if type(fields) is str:
                fields = fields.lower().strip().split(",")
            else:
                fields = ["id", "name", "description", "status", "created_at", "updated_at", "html_url"]

            if output != "raw":
                transformations = dict()

                for f in fields:
                    transformations[f] = Transformations.extract(f)
                    # special cases
                    if f == "status":
                        transformations[f] = Transformations.extract_decorate(
                            "status",
                            color_map={"active": "green", "warning": "yellow", "critical": "red", "unknown": "gray", "disabled": "gray"},
                            change_map={"active": "OK", "warning": "WARN", "critical": "CRIT", "unknown": "❔", "disabled": "off"},
                        )
                    if f == "url":
                        transformations[f] = Transformations.extract("html_url")
                    if f in ["created_at", "updated_at"]:
                        transformations[f] = Transformations.extract_date(f, "%Y-%m-%dT%H:%M:%S%z", timezone.utc)

                filtered = Transformations.apply(svcs, transformations)
            else:
                # raw output, using json format
                filtered = svcs

            # define here how print in "plain" way (ie if output=plain)
            def plain_print_f(i):
                s = ""
                for f in fields:
                    s += f"{i[f]}\t"
                print(s)

            if sort_by:
                sort_fields: str | list[str] = sort_by.split(",") if "," in sort_by else sort_by

                if isinstance(sort_fields, list) and len(sort_fields) > 1:
                    filtered = sorted(filtered, key=lambda x: [x[k] for k in sort_fields], reverse=reverse_sort)
                else:
                    filtered = sorted(filtered, key=lambda x: x[sort_fields], reverse=reverse_sort)

            print_items(filtered, output, plain_print_f=plain_print_f)
            return True

        except UnauthorizedException as e:
            print(f"[red]{e}[/red]")
            return False
        except KeyError:
            print(f"[red]Invalid sort field: {sort_by}[/red]")
            ff = ", ".join(fields) if fields else ""
            print(f"[yellow]Available fields: {ff}[/yellow]")
            return False

    @staticmethod
    def list_incidents(
        cfg: Config,
        everything: bool = False,
        user: Optional[str] = None,
        new: bool = True,
        ack: bool = False,
        output: str = "table",
        snooze: bool = False,
        resolve: bool = False,
        high: bool = False,
        low: bool = False,
        watch: bool = False,
        timeout: int = 30,
        regexp: Optional[str] = None,
        excluded_filter_re: Optional[str] = None,
        rules: bool = False,
        rules_path: str = "~/.config/pdh/rules",
        fields: Optional[List[str]] = None,
        alerts: bool = False,
        alert_fields: Optional[List[str]] = None,
        service_re: Optional[str] = None,
        excluded_service_re: Optional[str] = None,
        sort_by: Optional[str] = None,
        reverse_sort: bool = False,
        teams: Optional[str] = None,
    ) -> bool:
        pd = PagerDuty(cfg)

        # Prepare defaults
        status = [STATUS_TRIGGERED]
        urgencies = DEFAULT_URGENCIES
        if high:
            urgencies = [URGENCY_HIGH]
        if low:
            urgencies = [URGENCY_LOW]
        if not new:
            status.append(STATUS_ACK)
        userid = None
        if user:
            userid = pd.users.id(query=user, key="name")

        try:
            if regexp:
                filter_re = re.compile(regexp)
            if excluded_filter_re:
                filter_excluded_re = re.compile(excluded_filter_re)
        except re.error as e:
            print(f"[red]Invalid regular expression: {str(e)}[/red]")
            return False

        incs = []
        console = Console()
        # fallback to configured userid

        # set fields that will be displayed
        if type(fields) is str:
            fields = fields.lower().strip().split(",")
        else:
            fields = ["id", "assignee", "title", "status", "created_at", "service.summary"]
        if alerts:
            fields.append("alerts")

        if type(alert_fields) is str:
            alert_fields = alert_fields.lower().strip().split(",")
        else:
            alert_fields = ["status", "created_at", "service.summary", "body.details"]

        if type(teams) is str:
            if teams == "mine":
                teamNames = dict(pd.me)["teams"] if "teams" in dict(pd.me) else []
                teams = [t["id"] for t in teamNames if "id" in t]
            else:
                teams = teams.lower().strip().split(",")

        if not everything and not userid:
            userid = pd.cfg["uid"]
        while True:
            incs = pd.incidents.list(userid, statuses=status, urgencies=urgencies, teams=teams)

            if rules:
                scripts = []
                ppath = os.path.expanduser(os.path.expandvars(rules_path))
                for root, _, filenames in os.walk(ppath):
                    for filename in filenames:
                        fullpath = os.path.join(root, filename)
                        if os.access(fullpath, os.X_OK):
                            scripts.append(fullpath)

                if len(scripts) == 0:
                    print(f"[yellow]No rules found in {ppath}[/yellow]")

                def printFunc(name: str):
                    print("[green]Applied rule:[/green]", name)

                def errFunc(error: str):
                    print("[red]Error:[/red]", error)

                ret = pd.incidents.apply(incs, scripts, printFunc, errFunc)
                if type(ret) is not str:
                    incs = list(ret)
                else:
                    print(ret)

            if regexp:
                incs = Filters.apply(incs, filters=[Filters.regexp("title", filter_re)])

            if excluded_filter_re:
                incs = Filters.apply(incs, filters=[Filters.not_regexp("title", filter_excluded_re)])

            if service_re:
                incs = Transformations.apply(incs, {"service": Transformations.extract("service.summary")}, preserve=True)
                incs = Filters.apply(incs, [Filters.regexp("service", service_re)])

            if excluded_service_re:
                incs = Transformations.apply(incs, {"service": Transformations.extract("service.summary")}, preserve=True)
                incs = Filters.apply(incs, [Filters.not_regexp("service", excluded_service_re)])

            if alerts:
                for i in incs:
                    i["alerts"] = pd.incidents.alerts(i["id"])

            # Build filtered list for output
            if output != "raw":
                transformations = dict()
                for f in fields:
                    transformations[f] = Transformations.extract(f)
                    # special cases
                    if f == "assignee":
                        transformations[f] = Transformations.extract_assignees()
                    if f == "status":
                        transformations[f] = Transformations.extract_decorate(
                            "status",
                            color_map={STATUS_TRIGGERED: "red", STATUS_ACK: "yellow", STATUS_RESOLVED: "green"},
                            default_color="cyan",
                            change_map={STATUS_TRIGGERED: "✘", STATUS_ACK: "✔", STATUS_RESOLVED: "✔"},
                        )
                    if f == "url":
                        transformations[f] = Transformations.extract("html_url")
                    if f == "urgency":
                        transformations[f] = Transformations.extract_decorate(
                            "urgency", color_map={URGENCY_HIGH: "red", URGENCY_LOW: "green"}, change_map={URGENCY_HIGH: "HIGH", URGENCY_LOW: "LOW"}
                        )
                    if f == "service.summary":
                        transformations["service"] = Transformations.extract("service.summary")
                    if f in ["title", "urgency"]:

                        def mapper(item: str, d: dict) -> str:
                            if "urgency" in d and d["urgency"] == URGENCY_HIGH:
                                return f"[red]{item}[/red]"
                            return f"[cyan]{item}[/cyan]"

                        transformations[f] = Transformations.extract_decorate(f, default_color="cyan", color_map={URGENCY_HIGH: "red"}, map_func=mapper)
                    if f in ["created_at", "last_status_change_at"]:
                        transformations[f] = Transformations.extract_date(f, "%Y-%m-%dT%H:%M:%S%z", timezone.utc)
                    if f in ["alerts"]:
                        transformations[f] = Transformations.extract_alerts(f, alert_fields)
                filtered = Transformations.apply(incs, transformations)
            else:
                # raw output, using json format
                filtered = incs

            # define here how print in "plain" way (ie if output=plain)
            def plain_print_f(i):
                s = ""
                for f in fields:
                    s += f"{i[f]}\t"
                print(s)

            if sort_by:
                sort_fields: list[str] = sort_by.split(",") if "," in sort_by else [sort_by]
                try:
                    filtered = sorted(filtered, key=lambda x: [x[k] for k in sort_fields], reverse=reverse_sort)
                except KeyError:
                    print(f"[red]Invalid sort field: {sort_by}[/red]")
                    print(f"[yellow]Available fields: {', '.join(fields)}[/yellow]")
                    return False

            print_items(filtered, output, plain_print_f=plain_print_f)

            # now apply actions like snooze, resolve, ack...
            ids = [i["id"] for i in incs]
            if ack:
                pd.incidents.ack(incs)
                if output not in ["yaml", "json"]:
                    for i in ids:
                        print(f"Marked {i} as [yellow]ACK[/yellow]")
            if snooze:
                pd.incidents.snooze(incs)
                if output not in ["yaml", "json"]:
                    for i in ids:
                        print(f"Snoozing incident {i} for 4h")
            if resolve:
                pd.incidents.resolve(incs)
                if output not in ["yaml", "json"]:
                    for i in ids:
                        print(f"Mark {i} as [green]RESOLVED[/green]")

            if not watch:
                break
            time.sleep(timeout)
            console.clear()

    @staticmethod
    def ack(cfg: Config, incIDs: list = []) -> None:
        pd = PagerDuty(cfg)
        incs = pd.incidents.list()
        incs = Filter.apply(incs, filters=[Filter.inList("id", incIDs)])
        for i in incs:
            print(f"[yellow]✔[/yellow] {i['id']} [grey50]{i['title']}[/grey50]")
        pd.incidents.ack(incs)

    @staticmethod
    def resolve(cfg: Config, incIDs: list = []) -> None:
        pd = PagerDuty(cfg)
        incs = pd.incidents.list()
        incs = Filter.apply(incs, filters=[Filter.inList("id", incIDs)])
        for i in incs:
            print(f"[green]✅[/green] {i['id']} [grey50]{i['title']}[/grey50]")
        pd.incidents.resolve(incs)

    @staticmethod
    def snooze(cfg: Config, incIDs: list = [], duration: int = 14400) -> None:
        pd = PagerDuty(cfg)
        import datetime

        incs = pd.incidents.list()
        incs = Filter.apply(incs, filters=[Filter.inList("id", incIDs)])
        for id in incIDs:
            print(f"Snoozing incident {id} for {str(datetime.timedelta(seconds=duration))}")

        pd.incidents.snooze(incs, duration)

    @staticmethod
    def reassign(cfg: Config, incIDs: list = [], user: str | None = None):
        pd = PagerDuty(cfg)
        incs = pd.incidents.list()
        incs = Filter.apply(incs, filters=[Filter.inList("id", incIDs)])

        users = pd.users.id(user)
        if users is None or len(users) == 0:
            users = pd.users.id(user)

        for id in incIDs:
            print(f"Reassign incident {id} to {users}")

        pd.incidents.reassign(incs, users)
