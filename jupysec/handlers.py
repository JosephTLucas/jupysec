import os
import json
import subprocess
from pathlib import Path
import itertools
import time
from jinja2 import Environment, FileSystemLoader

from jupyter_server.base.handlers import APIHandler
from jupyter_server.utils import url_path_join

import tornado
from tornado.web import StaticFileHandler

from jupysec.rules import Rules
class FileHandler():
    def __init__(self):
        self.in_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.out_dir = os.path.join(os.path.dirname(__file__), "public")

    def write_to_template(self, content):
        env = Environment(loader=FileSystemLoader(self.in_dir))
        results_template = env.get_template("index.html")
        with open(f"{self.out_dir}/score.html", "w") as f:
            f.write(results_template.render(content))


class RouteHandler(APIHandler):
    # The following decorator should be present on all verb methods (head, get, post,
    # patch, put, delete, options) to ensure only authorized user can request the
    # Jupyter server
    @tornado.web.authenticated
    def get(self):
        r = Rules()
        findings = r.get_findings()
        f = FileHandler()
        f.write_to_template({"findings": findings, "time": str(time.time())})
        self.finish(json.dumps({"data": "complete"}))

    @tornado.web.authenticated
    def post(self):
        # input_data is a dictionary with a key "name"
        input_data = self.get_json_body()
        data = {"greetings": "Hello {}, enjoy JupyterLab!".format(input_data["name"])}
        self.finish(json.dumps(data))


def setup_handlers(web_app, url_path):
    host_pattern = ".*$"
    base_url = web_app.settings["base_url"]

    # Prepend the base_url so that it works in a JupyterHub setting
    route_pattern = url_path_join(base_url, url_path, "scorecard_update")
    handlers = [(route_pattern, RouteHandler)]
    web_app.add_handlers(host_pattern, handlers)

    # Prepend the base_url so that it works in a JupyterHub setting
    doc_url = url_path_join(base_url, url_path, "public")
    doc_dir = os.path.join(os.path.dirname(__file__), "public")
    handlers = [("{}/(.*)".format(doc_url), StaticFileHandler, {"path": doc_dir})]
    web_app.add_handlers(".*$", handlers)