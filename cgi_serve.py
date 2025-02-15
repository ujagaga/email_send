#!/usr/bin/env python3

import os
from wsgiref.handlers import CGIHandler
from index import app

os.environ.setdefault("REQUEST_METHOD", "GET")

CGIHandler().run(app)