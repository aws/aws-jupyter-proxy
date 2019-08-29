from botocore.session import Session
from notebook.utils import url_path_join

from aws_jupyter_proxy.awsproxy import create_endpoint_resolver, AwsProxyHandler

awsproxy_handlers = [
    (
        r"/awsproxy(.*)",
        AwsProxyHandler,
        dict(endpoint_resolver=create_endpoint_resolver(), session=Session()),
    )
]


def setup_handlers(web_app):
    base_url = web_app.settings["base_url"]
    web_app.add_handlers(
        ".*",
        [
            (url_path_join(base_url, path), handler, data)
            for (path, handler, data) in awsproxy_handlers
        ],
    )
