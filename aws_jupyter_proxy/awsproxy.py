import hashlib
import hmac
import os
import re
from collections import namedtuple
from functools import lru_cache
from typing import List, Tuple
from urllib.parse import urlparse, urlunparse, quote

from botocore.client import ClientEndpointBridge
from botocore.loaders import create_loader
from botocore.model import ServiceModel
from botocore.regions import EndpointResolver
from botocore.session import Session
from notebook.base.handlers import APIHandler
from tornado.httpclient import (
    AsyncHTTPClient,
    HTTPRequest,
    HTTPResponse,
    HTTPClientError,
    HTTPError,
)
from tornado.httputil import HTTPServerRequest, HTTPHeaders

ServiceInfo = namedtuple(
    "ServiceInfo", ["service_name", "host", "endpoint_url", "credential_scope"]
)
UpstreamAuthInfo = namedtuple(
    "UpstreamAuthInfo", ["service_name", "region", "signed_headers"]
)


# maxsize is arbitrarily taken from https://docs.python.org/3/library/functools.html#functools.lru_cache
@lru_cache(maxsize=128)
def get_service_info(
    endpoint_resolver: EndpointResolver,
    service_name: str,
    region: str,
    endpoint_override: str,
) -> ServiceInfo:
    service_model_json = create_loader().load_service_model(service_name, "service-2")

    service_data = ClientEndpointBridge(endpoint_resolver).resolve(
        service_name=ServiceModel(
            service_model_json, service_name=service_name
        ).endpoint_prefix,
        region_name=region,
    )

    if endpoint_override and re.fullmatch(
        r"https:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.(aws.dev|amazonaws.com)\b",
        endpoint_override,
    ):
        service_data["endpoint_url"] = endpoint_override

    return ServiceInfo(
        service_name,
        service_data["metadata"]["hostname"],
        service_data["endpoint_url"],
        service_data["metadata"].get("credentialScope"),
    )


def create_endpoint_resolver() -> EndpointResolver:
    """
    Creates an instance of the botocore EndpointResolver. Used to inject the instance during application initialization
    to avoid loading endpoint data on a per-request basis.
    :return: the EndpointResolver instance
    """
    return EndpointResolver(create_loader().load_data("endpoints"))


class AwsProxyHandler(APIHandler):
    def initialize(self, endpoint_resolver: EndpointResolver, session: Session):
        """
        Hook for Tornado handler initialization.
        :param session: the botocore session
        :param endpoint_resolver: the application level EndpointResolver instance
        """
        self.endpoint_resolver = endpoint_resolver
        self.session = session

    async def handle_request(self):
        try:
            response = await AwsProxyRequest(
                self.request, self.endpoint_resolver, self.session
            ).execute_downstream()
            self.set_status(response.code, response.reason)
            self._finish_response(response)
        except HTTPClientError as e:
            self.set_status(e.code, e.message)
            if e.response:
                self._finish_response(e.response)
            else:
                super(APIHandler, self).finish()

    def _finish_response(self, response: HTTPResponse):
        for name, value in response.headers.get_all():
            if self._is_blacklisted_response_header(name, value):
                continue
            self.set_header(name, value)
        csp_value = response.headers.get(
            "Content-Security-Policy", "upgrade-insecure-requests; base-uri 'none';"
        )
        self.set_header("Content-Security-Policy", csp_value)
        super(APIHandler, self).finish(response.body or None)

    async def post(self, *args):
        await self.handle_request()

    async def get(self, *args):
        await self.handle_request()

    async def delete(self, *args):
        await self.handle_request()

    async def patch(self, *args):
        await self.handle_request()

    async def put(self, *args):
        await self.handle_request()

    async def head(self, *args):
        await self.handle_request()

    @staticmethod
    def _is_blacklisted_response_header(name: str, value: str) -> bool:
        if name == "Transfer-Encoding" and value == "chunked":
            # Responses are no longer "chunked" when we send them to the browser.
            # If we retain this header, then the browser will wait forever for more chunks.
            return True
        elif name == "Content-Length":
            # Tornado will auto-set the Content-Length
            return True
        else:
            return False


class AwsProxyRequest(object):
    """
    A class representing a request being proxied from an upstream client (browser) to the downstream AWS service.
    """

    BLACKLISTED_REQUEST_HEADERS: List[str] = ["Origin", "Host"]

    def __init__(
        self,
        upstream_request: HTTPServerRequest,
        endpoint_resolver: EndpointResolver,
        session: Session,
    ):
        """
        :param upstream_request: The original upstream HTTP request from the client(browser) to Jupyter
        :param endpoint_resolver: The botocore endpoint_resolver instance
        """
        self.upstream_request = upstream_request
        self.endpoint_resolver = endpoint_resolver

        self.credentials = session.get_credentials()

        self.upstream_auth_info = self._build_upstream_auth_info()
        self.service_info = get_service_info(
            endpoint_resolver,
            self.upstream_auth_info.service_name,
            self.upstream_auth_info.region,
            self.upstream_request.headers.get("X-service-endpoint-url", None),
        )
        # if the environment variable is not specified, os.getenv returns None, and no whitelist is in effect.
        self.whitelisted_services = (
            os.getenv("AWS_JUPYTER_PROXY_WHITELISTED_SERVICES").strip(",").split(",")
            if os.getenv("AWS_JUPYTER_PROXY_WHITELISTED_SERVICES") is not None
            else None
        )

    async def execute_downstream(self) -> HTTPResponse:
        """
        Executes the downstream request (Jupyter to AWS service) and return the response or the error
        after adding SigV4 authentication.

        "allow_nonstandard_methods" is used because Tornado rejects POST requests without a body without this parameter,
        and some operations send such requests (such as S3.InitiateMultipartUpload)
        :return: the HTTPResponse
        """
        if (
            self.whitelisted_services is not None
            and self.service_info.service_name not in self.whitelisted_services
        ):
            raise HTTPError(
                403,
                message=f"Service {self.service_info.service_name} is not whitelisted for proxying requests",
            )

        base_service_url = urlparse(self.service_info.endpoint_url)
        start_index = self.upstream_request.path.index("/awsproxy") + len("/awsproxy")
        downstream_request_path = (
            base_service_url.path + self.upstream_request.path[start_index:] or "/"
        )
        return await AsyncHTTPClient().fetch(
            HTTPRequest(
                method=self.upstream_request.method,
                url=self._compute_downstream_url(downstream_request_path),
                headers=self._compute_downstream_headers(downstream_request_path),
                body=self.upstream_request.body or None,
                follow_redirects=False,
                allow_nonstandard_methods=True,
            )
        )

    def _compute_downstream_url(self, downstream_request_path) -> str:
        base_service_url = urlparse(self.service_info.endpoint_url)
        return urlunparse(
            [
                base_service_url.scheme,
                base_service_url.netloc,
                downstream_request_path,
                base_service_url.params,
                self.upstream_request.query,
                None,
            ]
        )

    def _compute_downstream_headers(self, downstream_request_path) -> HTTPHeaders:
        """
        1. Copy original headers apart from blacklisted ones
        2. Add the Host header based on the service model
        3. Add a security token header if the current session is using temporary credentials
        4. Add the SigV4 Authorization header.

        :param downstream_request_path: the URL path for the downstream service request
        :return: the headers to pass to the downstream request
        """
        downstream_request_headers = self.upstream_request.headers.copy()
        for blacklisted_request_header in self.BLACKLISTED_REQUEST_HEADERS:
            try:
                del downstream_request_headers[blacklisted_request_header]
            except KeyError:
                pass

        base_service_url = urlparse(self.service_info.endpoint_url)
        downstream_request_headers["Host"] = base_service_url.netloc

        if self.credentials.token:
            downstream_request_headers["X-Amz-Security-Token"] = self.credentials.token

        downstream_request_headers["Authorization"] = self._sigv4_auth_header(
            downstream_request_path
        )
        return downstream_request_headers

    def _sigv4_auth_header(self, downstream_request_path) -> str:
        """
        Computes the SigV4 signature following https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html

        :param downstream_request_path: the URL path for the downstream service's request
        :return: the Authorization header containing SigV4 credetntials
        """
        # ************* TASK 1: CREATE THE CANONICAL REQUEST*************
        canonical_method = self.upstream_request.method
        canonical_uri = quote(downstream_request_path)
        canonical_querystring = self._get_canonical_querystring()
        signed_headers, canonical_headers = self._get_signed_canonical_headers()
        payload_hash = hashlib.sha256(self.upstream_request.body).hexdigest()

        canonical_request = (
            f"{canonical_method}\n"
            f"{canonical_uri}\n"
            f"{canonical_querystring}\n"
            f"{canonical_headers}\n"
            f"{signed_headers}\n"
            f"{payload_hash}"
        )

        # ************* TASK 2: CREATE THE STRING TO SIGN*************
        algorithm = "AWS4-HMAC-SHA256"
        region = self._get_downstream_signing_region()
        amz_date = self.upstream_request.headers["X-Amz-Date"]
        date_stamp = amz_date[0:8]

        credential_scope = (
            f"{date_stamp}/{region}/{self.service_info.service_name}/aws4_request"
        )
        request_digest = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        string_to_sign = (
            f"{algorithm}\n" f"{amz_date}\n" f"{credential_scope}\n" f"{request_digest}"
        )

        # ************* TASK 3: CALCULATE THE SIGNATURE *************
        signing_key = get_signature_key(
            self.credentials.secret_key,
            date_stamp,
            region,
            self.service_info.service_name,
        )
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        # ************* TASK 4: BUILD THE AUTH HEADER *************
        authorization_header = (
            f"{algorithm} "
            f"Credential={self.credentials.access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )

        return authorization_header

    def _get_canonical_querystring(self) -> str:
        canonical_query_string = ""
        corrected_request_query = self.upstream_request.query.replace("+", "%20")
        if corrected_request_query != "":
            query_string_list = []
            for item in corrected_request_query.split("&"):
                query_string_part = item.split("=", maxsplit=1)
                if len(query_string_part) == 2:
                    query_string_list.append(query_string_part)
                elif len(query_string_part) == 1:
                    query_string_part.append("")
                    query_string_list.append(query_string_part)
                else:
                    raise ValueError(f"Invalid query string split for {item}")
            query_string_dict = dict(query_string_list)
            sorted_q_string_list = [
                f"{k}={query_string_dict[k]}" for k in sorted(query_string_dict)
            ]
            canonical_query_string = "&".join(sorted_q_string_list)
        return canonical_query_string

    def _get_signed_canonical_headers(self) -> Tuple[str, str]:
        canonical_headers = {}

        for signed_header in self.upstream_auth_info.signed_headers:
            canonical_headers[signed_header] = self.upstream_request.headers[
                signed_header
            ]

        base_service_url = urlparse(self.service_info.endpoint_url)
        canonical_headers["host"] = base_service_url.netloc
        if self.credentials.token:
            canonical_headers["x-amz-security-token"] = self.credentials.token

        canonical_headers_string = "\n".join(
            [
                f"{canonical_header}:{canonical_headers[canonical_header]}"
                for canonical_header in sorted(canonical_headers)
            ]
        )
        canonical_headers_string += "\n"
        signed_headers = ";".join(sorted(canonical_headers))

        return signed_headers, canonical_headers_string

    def _get_downstream_signing_region(self) -> str:
        """
        Get the region to sign the downstream request for. The default is the region that the request was originally
        signed,  but if the service has a credentialScope override specified in the service config then that is used.
        :return: the region to sign the request with.
        """
        if not self.service_info.credential_scope:
            return self.upstream_auth_info.region

        try:
            return self.service_info.credential_scope["region"]
        except KeyError:
            return self.upstream_auth_info.region

    def _build_upstream_auth_info(self) -> UpstreamAuthInfo:
        """
        Parses the upstream requests's Authorization header to determine identifying information such as the region and
        the service the request was originally signed for.

        Sample header:
            AWS4-HMAC-SHA256 \
            Credential=SOMEACCESSKEY/20190814/aws_region/aws_service/aws4_request, \
            SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-target;x-amz-user-agent, \
            Signature=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

        :return: the UpstreamAuthInfo instance
        """
        auth_header_parts = self.upstream_request.headers["Authorization"].split(" ")

        signed_headers = auth_header_parts[2].strip(",").split("=")[1].split(";")
        _, _, region, service_name, _ = auth_header_parts[1].split("=")[1].split("/")
        return UpstreamAuthInfo(service_name, region, signed_headers)


# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(key, date_stamp, region_name, service_name):
    k_date = sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = sign(k_date, region_name)
    k_service = sign(k_region, service_name)
    k_signing = sign(k_service, "aws4_request")
    return k_signing
