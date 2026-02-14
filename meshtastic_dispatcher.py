# GuardianBridge - A Meshtastic Gateway for Community Resilience
# Copyright (C) 2025 Robert Kolbasowski
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Entrypoint for the GuardianBridge dispatcher."""

import gb_db
import settings

from dispatcher import core as core
import dispatcher.commands as commands
import dispatcher.messaging as messaging
import dispatcher.sos as sos
import dispatcher.weather as weather

from dispatcher.core import *
from dispatcher.commands import *
from dispatcher.commands import _cmd_send_email
from dispatcher.sos import *
from dispatcher.weather import *
from dispatcher.messaging import *
from dispatcher.email_queue import *


if __name__ == "__main__":
    main()
