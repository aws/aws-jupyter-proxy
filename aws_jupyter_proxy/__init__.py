from aws_jupyter_proxy.handlers import setup_handlers


def _jupyter_server_extension_paths():
    return [{"module": "aws_jupyter_proxy"}]


def load_jupyter_server_extension(nbapp):
    setup_handlers(nbapp.web_app)
