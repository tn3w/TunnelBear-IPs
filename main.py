#!/usr/bin/env python3

import json
import time
import traceback
import uuid
import os
import random
import urllib.request
import urllib.parse
import http.cookiejar
import gzip
import io
from typing import List, Tuple, Final

TUNNELBEAR_IPS_FILE: Final[str] = "new_tunnelbear_ips.json"
USER_AGENT: Final[str] = (
    "Mozilla/5.0 "
    "(Windows NT 10.0; Win64; x64; rv:138.0.1) "
    "Gecko/20100101 "
    "Firefox/138.0.1"
)
TB_API_URL: Final[str] = "https://api.tunnelbear.com"
PB_API_URL: Final[str] = "https://api.polargrizzly.com"

COUNTRIES: Final[List[str]] = [
    "ar",
    "au",
    "at",
    "be",
    "br",
    "bg",
    "ca",
    "cl",
    "co",
    "cy",
    "cz",
    "dk",
    "fi",
    "fr",
    "de",
    "gr",
    "hu",
    "id",
    "ie",
    "it",
    "jp",
    "ke",
    "kr",
    "lv",
    "lt",
    "my",
    "mx",
    "md",
    "nl",
    "nz",
    "ng",
    "no",
    "pe",
    "ph",
    "pl",
    "pt",
    "ro",
    "rs",
    "sg",
    "si",
    "za",
    "es",
    "se",
    "ch",
    "tw",
    "ae",
    "gb",
    "us",
]


def read_response(response):
    """Read response data, handling gzip compression if necessary"""
    if response.info().get("Content-Encoding") == "gzip":
        gzip_file = gzip.GzipFile(fileobj=io.BytesIO(response.read()))
        content = gzip_file.read()
        return content.decode("utf-8")
    return response.read().decode("utf-8")


def get_tunnelbear_cookies():
    """Get TunnelBear cookies and CSRF token using direct API endpoint"""
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
        "tunnelbear-app-id": "com.tunnelbear.web",
        "tunnelbear-app-version": "1.0.0",
        "tunnelbear-platform": "Firefox",
        "tunnelbear-platform-version": "138",
        "Origin": "https://www.tunnelbear.com",
        "Referer": "https://www.tunnelbear.com/",
    }

    request = urllib.request.Request(
        "https://prod-api-core.tunnelbear.com/core/web/xzrf",
        headers=headers,
        method="GET",
    )

    response = opener.open(request)

    csrf_token = None

    if "tb-csrf-token" in response.headers:
        csrf_token = response.headers["tb-csrf-token"]

    return cookie_jar, csrf_token


def authenticate_tunnelbear(cookies, csrf_token, email, password):
    """Authenticate with TunnelBear using cookies and CSRF token"""
    if not cookies or not csrf_token:
        print("Error: Missing cookies or CSRF token")
        return None, None, None

    try:
        device_id = f"browser-{str(uuid.uuid4())}"

        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookies)
        )

        headers = {
            "Host": "prod-api-dashboard.tunnelbear.com",
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "TB-CSRF-Token": csrf_token,
            "tunnelbear-app-id": "com.tunnelbear.web",
            "tunnelbear-app-version": "1.0.0",
            "tunnelbear-platform": "Chrome",
            "tunnelbear-platform-version": "113",
            "Origin": "https://www.tunnelbear.com",
            "Referer": "https://www.tunnelbear.com/",
        }

        auth_data = {
            "username": email,
            "password": password,
            "grant_type": "password",
            "device": device_id,
        }

        url = "https://prod-api-dashboard.tunnelbear.com/dashboard/web/v2/token"
        data = json.dumps(auth_data).encode("utf-8")

        request = urllib.request.Request(url, data=data, headers=headers, method="POST")

        response = opener.open(request)
        response_data = read_response(response)

        if response.getcode() != 200:
            print(f"Authentication failed: {response_data}")
            return None, None, None

        response_json = json.loads(response_data)

        if "access_token" not in response_json:
            print(f"Authentication failed: {response_json}")
            return None, None, None

        access_token = response_json["access_token"]

        cookie_url = (
            "https://prod-api-dashboard.tunnelbear.com/dashboard/web/v2/tokenCookie"
        )
        cookie_headers = headers.copy()
        cookie_headers["Authorization"] = f"Bearer {access_token}"
        cookie_headers["Content-Type"] = (
            "application/x-www-form-urlencoded;charset=utf-8"
        )

        cookie_request = urllib.request.Request(
            cookie_url, data=None, headers=cookie_headers, method="POST"
        )

        opener.open(cookie_request)

        play_session = None
        csrf_token_updated = None

        for cookie in cookies:
            if cookie.name == "PLAY_SESSION":
                play_session = cookie.value
            if cookie.name == "XSRF-TOKEN":
                csrf_token_updated = cookie.value

        return access_token, play_session, csrf_token_updated

    except Exception as e:
        print(f"Error during authentication: {e}")
        traceback.print_exc()
        return None, None, None


class TunnelBearAPI:
    """Class to handle TunnelBear authentication and server fetching"""

    def __init__(self, credentials: List[Tuple[str, str]]):
        self.credentials = credentials
        self.tb_cookiejar = http.cookiejar.CookieJar()
        self.pb_cookiejar = http.cookiejar.CookieJar()

        self.tb_opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.tb_cookiejar)
        )
        self.pb_opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.pb_cookiejar)
        )

        self.tb_token = None
        self.pb_token = None
        self.csrf_token = None

        self.authenticate()

    def authenticate(self):
        """Get fresh TunnelBear authentication"""
        print("Getting fresh TunnelBear authentication...")

        cookies, csrf_token = get_tunnelbear_cookies()

        if not csrf_token:
            raise Exception("Failed to get CSRF token. Cannot authenticate.")

        random_credential = random.choice(self.credentials)

        self.tb_token, play_session, self.csrf_token = authenticate_tunnelbear(
            cookies, csrf_token, random_credential[0], random_credential[1]
        )

        if not self.tb_token:
            raise Exception("Authentication failed")

        if play_session:
            play_session_cookie = http.cookiejar.Cookie(
                version=0,
                name="PLAY_SESSION",
                value=play_session,
                port=None,
                port_specified=False,
                domain="tunnelbear.com",
                domain_specified=True,
                domain_initial_dot=False,
                path="/",
                path_specified=True,
                secure=True,
                expires=None,
                discard=False,
                comment=None,
                comment_url=None,
                rest={},
            )
            self.tb_cookiejar.set_cookie(play_session_cookie)

        if self.csrf_token:
            xsrf_cookie = http.cookiejar.Cookie(
                version=0,
                name="XSRF-TOKEN",
                value=self.csrf_token,
                port=None,
                port_specified=False,
                domain="tunnelbear.com",
                domain_specified=True,
                domain_initial_dot=False,
                path="/",
                path_specified=True,
                secure=True,
                expires=None,
                discard=False,
                comment=None,
                comment_url=None,
                rest={},
            )
            self.tb_cookiejar.set_cookie(xsrf_cookie)

        print("Successfully authenticated with TunnelBear")

    def exchange_token(self):
        """Exchange TunnelBear token for PolarBear token"""
        if not self.tb_token:
            raise Exception("No TunnelBear token available. Authenticate first.")

        payload = {"partner": "tunnelbear", "token": self.tb_token}
        payload_bytes = json.dumps(payload).encode("utf-8")

        try:
            headers = {"Content-Type": "application/json"}

            pb_auth_request = urllib.request.Request(
                f"{PB_API_URL}/auth", data=payload_bytes, headers=headers, method="POST"
            )

            pb_auth_response = self.pb_opener.open(pb_auth_request)

            if pb_auth_response.getcode() != 200:
                response_data = read_response(pb_auth_response)
                raise Exception(f"Token exchange failed: {response_data}")

            auth_header = pb_auth_response.headers.get("authorization", "")
            self.pb_token = auth_header.replace("Bearer ", "") if auth_header else ""

            if not self.pb_token:
                raise Exception("No authorization header in response")

            print("Token exchange successful!")
            return True

        except Exception as e:
            print(f"Error exchanging token: {e}")
            raise Exception(f"Failed to get PolarBear token: {e}")

    def get_servers(self, country=None):
        """Get server information for a country or closest region"""
        if not self.pb_token:
            raise Exception("Not authenticated. Call exchange_token() first.")

        headers = {"authorization": f"Bearer {self.pb_token}"}

        if country is None:
            url = f"{PB_API_URL}/vpns"
        else:
            url = f"{PB_API_URL}/vpns/countries/{country}"

        try:
            server_request = urllib.request.Request(url, headers=headers, method="GET")

            response = self.pb_opener.open(server_request)

            if response.getcode() != 200:
                response_data = read_response(response)
                raise Exception(f"Failed to get servers: {response_data}")

            response_data = read_response(response)
            response_json = json.loads(response_data)
            return response_json

        except Exception as e:
            raise Exception(f"Failed to get servers: {str(e)}") from e


def get_credentials_from_env() -> List[Tuple[str, str]]:
    """Get TunnelBear credentials from environment variables.

    Looks for variables in the format:
    - tunnelbear_email, tunnelbear_password
    - tunnelbear_email1, tunnelbear_password1
    - tunnelbear_email2, tunnelbear_password2
    ... and so on
    """
    credentials = []

    base_email = os.environ.get("tunnelbear_email")
    base_password = os.environ.get("tunnelbear_password")

    if base_email and base_password:
        credentials.append((base_email, base_password))

    i = 1
    while True:
        email = os.environ.get(f"tunnelbear_email{i}")
        password = os.environ.get(f"tunnelbear_password{i}")

        if not email or not password:
            break

        credentials.append((email, password))
        i += 1

    return credentials


def load_dotenv(env_file=".env"):
    """
    Load environment variables from a .env file into os.environ

    Args:
        env_file: Path to the .env file (default: ".env")
    """
    if not os.path.exists(env_file):
        return

    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]

                os.environ[key] = value

    print(f"Loaded environment variables from {env_file}")


def main() -> None:
    """Main function to run the script"""
    load_dotenv()

    if os.path.exists(TUNNELBEAR_IPS_FILE):
        with open(TUNNELBEAR_IPS_FILE, "r", encoding="utf-8") as f:
            servers = json.load(f)
    else:
        servers = []

    random.shuffle(COUNTRIES)

    credentials = get_credentials_from_env()

    if not credentials:
        print(
            "No credentials found in environment variables.",
            "Please set tunnelbear_email and tunnelbear_password.",
        )
        return

    print(f"Found {len(credentials)} credential sets")

    api = TunnelBearAPI(credentials)

    for i in range(1000):
        if i+1 % 10 == 0:
            print("Refreshing authentication...")
            api.authenticate()

        api.exchange_token()

        for country in COUNTRIES:
            time.sleep(random.uniform(0.3, 0.5))
            print(f"Checking country: {country}")
            try:
                response = api.get_servers(country)
            except Exception as e:
                print(f"Error for country {country}: {e}")
                continue

            if "vpns" in response and isinstance(response["vpns"], list):
                for vpn in response["vpns"]:
                    servers.append(vpn["host"])
                print(f"Found {len(response['vpns'])} servers for {country}")

        unique_servers = list(set(servers))
        print(f"Total found: {len(unique_servers)} unique servers")

        with open(TUNNELBEAR_IPS_FILE, "w", encoding="utf-8") as f:
            json.dump(unique_servers, f)


if __name__ == "__main__":
    main()
