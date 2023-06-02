import os
import json
import subprocess
from pathlib import Path
import itertools
import time
from jinja2 import Environment, FileSystemLoader

from jupyter_server.base.handlers import APIHandler
from jupyter_server.utils import url_path_join
from jupyter_server.base.handlers import JupyterHandler

import tornado
from tornado.web import StaticFileHandler

from jupysec.rules import Rules
import pickle


class FileHandler():
    def __init__(self):
        self.in_dir = os.getenv(
            "JLAB_SERVER_EXAMPLE_STATIC_DIR",
            os.path.join(os.path.dirname(__file__), "templates"),
        )
        self.out_dir = os.getenv(
            "JLAB_SERVER_EXAMPLE_STATIC_DIR",
            os.path.join(os.path.dirname(__file__), "public"),
        )

    def write_to_template(self, content, template, out):
        env = Environment(loader=FileSystemLoader(self.in_dir))
        results_template = env.get_template(template)
        with open(f"{self.out_dir}/{out}", "w") as f:
            f.write(results_template.render(content))

def is_jsonable(x):
    try:
        json.dumps(x)
        return True
    except:
        return False


class RouteHandler(APIHandler):
    # The following decorator should be present on all verb methods (head, get, post,
    # patch, put, delete, options) to ensure only authorized user can request the
    # Jupyter server
    @tornado.web.authenticated
    def get(self):
        for filename in Path("jupysec_extension/public/").glob("*.html"):
            filename.unlink()
        r = Rules(config=config)
        findings = r.get_findings()
        f = FileHandler()
        for finding in findings:
            f.write_to_template({"finding": finding, "time": str(time.time())}, "finding.html", f"{finding.uuid}.html")
        f.write_to_template({"config": r.running_config.items(), "findings": findings, "time": str(time.time())}, "index.html", "score.html")
        '''
        # dumping the config to a file for debugging
        keys = list()
        for k,v in config.items():
            if is_jsonable(v):
                keys.append(k)
        with open("config.json", "w") as f:
            json.dump({key: value for (key, value) in config.items() if key in keys}, f)
        '''
        self.finish(json.dumps({"data": "complete"}))


def setup_handlers(web_app, url_path):
    host_pattern = ".*$"
    base_url = web_app.settings["base_url"]
    global config
    config = web_app.settings

    # Prepend the base_url so that it works in a JupyterHub setting
    route_pattern = url_path_join(base_url, url_path, "scorecard_update")
    handlers = [(route_pattern, RouteHandler)]
    web_app.add_handlers(host_pattern, handlers)

    # Prepend the base_url so that it works in a JupyterHub setting
    doc_url = url_path_join(base_url, url_path, "public")
    doc_dir = os.getenv(
        "JLAB_SERVER_EXAMPLE_STATIC_DIR",
        os.path.join(os.path.dirname(__file__), "public"),
    )
    handlers = [("{}/(.*)".format(doc_url), StaticFileHandler, {"path": doc_dir})]
    web_app.add_handlers(".*$", handlers)