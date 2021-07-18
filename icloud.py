import json
import logging
import uuid

import requests

logging.basicConfig()
logger = logging.getLogger(__name__)


class ICloudService(object):
    """Service contains the information for each icloud service"""
    def __init__(self, name, data=None):
        self.name = name
        self.url = data.get("url")
        self.status = data.get("status")
        self.raw_data = data

    @classmethod
    def from_json(cls, name, data):
        return cls(name, data)


class ICloudSession(object):
    """ICloudSession handles authentication and 2FA when logging into icloud and exposes icloud services"""
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session_token = None
        self.auth_headers = dict()
        self.client_id = "auth-" + str(uuid.uuid1()).lower()

    def authenticate(self):
        url = "https://idmsa.apple.com/appleauth/auth/signin"
        data = {
            "accountName": self.username,
            "rememberMe": False,
            "password": self.password,
            "trustTokens": list()
        }

        # values from time of dev, this might change later on
        headers = {
            "X-Apple-Oauth-Redirect-Uri": "https://www.icloud.com",
            "X-Apple-Oauth-Require-Grant-Code": "true",
            "X-Apple-Oauth-Client-Id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
            "X-Apple-Oauth-Client-Type": "firstPartyAuth",
            "X-Apple-Oauth-Response-Type": "code",
            "X-Apple-Oauth-Response-Mode": "web_message",
            "X-Apple-Oauth-State": self.client_id,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        # send the authentication request with credentials
        logger.info("Sending authentication request")
        resp = self.session.post(url, headers=headers, json=data)
        if resp.status_code != 409:
            raise Exception("Invalid credentials provided. Failed with status code: {code} and error: {error}".format(code=resp.status_code, error=resp.text))

        # set authentication headers
        self.auth_headers = headers
        self._set_auth_headers(resp)

        # check authentication type
        # TODO: figure out other authentication types
        try:
            resp.json()
        except json.decoder.JSONDecodeError:
            logger.error("error when decoding authentication response")
            raise Exception("failed to decode JSON output. request output: {text}".format(text=resp.text))
        auth_type = resp.json().get("authType")
        if auth_type and auth_type == "hsa2":
            logger.info("Authentication type is 2FA")
            if not self._authenticate_2fa():
                raise Exception("failed to authenticate with 2FA")

        logger.info("Successfully logged in")

    def _set_auth_headers(self, resp: requests.Response):
        for k, v in resp.headers.items():
            if k.startswith("X-Apple") or k.lower() == "scnt":
                self.auth_headers[k] = v

    @staticmethod
    def _wait_for_2fa_code() -> str:
        msg = "Approve from another device and input 2FA code: "
        code = input(msg).strip().replace(" ", "")
        # purely aesthetic
        print()
        while not code.isnumeric():
            logger.error("Invalid 2FA code. Try again...")
            code = input(msg).strip().replace(" ", "")
            # same reason as above
            print()
        return code

    # Note: when using burp suite, not sure why this call doesn't always get called
    def _authenticate_2fa(self):
        code = self._wait_for_2fa_code()
        url = "https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode"
        data = {
            "securityCode": {
                "code": code
            }
        }
        logger.info("Sending 2FA request")
        resp = self.session.post(url, headers=self.auth_headers, json=data)
        if not resp.status_code == 204:
            return False

        logger.info("Successfully authenticated with 2FA")
        return True

    def get_services(self) -> list[ICloudService]:
        # not sure when these values change
        client_build_number = "2112Project32"
        client_mastering_number = "2112B28"
        url = (f"https://setup.icloud.com/setup/ws/1/accountLogin?clientBuildNumber={client_build_number}"
               + f"&clientMasteringNumber={client_mastering_number}&clientId={self.client_id}")
        data = {
            "dsWebAuthToken": self.auth_headers.get("X-Apple-Session-Token"),
            "accountCountryCode": self.auth_headers.get("X-Apple-ID-Account-Country"),
            "extended_login": False
        }
        # setup endpoint expects origin to be set
        headers = {
            "Origin": "https://www.icloud.com"
        }
        resp = self.session.post(url, headers=headers, json=data)

        # status code should be 200 but this should be okay
        if not resp.ok:
            raise Exception("error getting services")

        # process services
        try:
            resp.json()
        except json.decoder.JSONDecodeError:
            logger.error("error when decoding get service request")
            raise Exception("failed to decode JSON output. request output: {text}".format(text=resp.text))
        service_data = resp.json().get("webservices")
        services = list()
        for service_name, service_datum in service_data.items():
            services.append(ICloudService.from_json(service_name, service_datum))
        return services
