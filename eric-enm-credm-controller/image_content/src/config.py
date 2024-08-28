#!flask/bin/python

#################################
#                               #
#  GUNICORN SETTING             #
#                               #
#################################

import multiprocessing
from os import environ as env
#import hooks

PORT = int(env.get("REST_PORT", 5001))

# Gunicorn config
bind = "0.0.0.0:" + str(PORT)
pidfile = "/credm/pid.id"

#workers = multiprocessing.cpu_count() * 2 + 1
#threads = 2 * multiprocessing.cpu_count()
workers = 1
threads = 1
timeout = 120
#max_requests = 0
limit_request_line = 1024
limit_request_fields = 100
limit_request_field_size = 1024

# Server Hooks
#worker_abort = hooks.worker_abort

