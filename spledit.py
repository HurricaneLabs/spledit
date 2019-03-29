import argparse
import configparser
import getpass
import logging
import subprocess
import sys
import tempfile
import warnings

import pyotp
import requests
from six.moves.urllib.parse import urljoin, quote
try:
    # pylint: disable=ungrouped-imports
    from requests.packages.urllib3 import exceptions
except ImportError:
    # Apparently, some linux distros strip the packages out of requests
    # I'm not going to tell you what I think of that, just going to deal with it
    from urllib3 import exceptions



logger = logging.getLogger(__name__)
warnings.simplefilter("ignore", exceptions.InsecureRequestWarning)


class SplunkSession(requests.Session):
    is_authenticated = False

    def __init__(self, address, *args, **kwargs):
        self.cookiejar = kwargs.pop("cookiejar", None)
        totp_secret = kwargs.pop("totp_secret", None)
        username = kwargs.pop("username", None)
        password = kwargs.pop("password", None)
        proxies = kwargs.pop("proxies", None)

        super(SplunkSession, self).__init__(*args, **kwargs)

        if proxies:
            self.proxies = proxies

        self.address = address
        self.verify = False

        if "output_mode" not in self.params:
            self.params["output_mode"] = "json"

        r = self.get("/services/authentication/current-context")
        if r.status_code == 401:
            # Need to authenticate
            logger.info("Need to authenticate to %s", address)
            if username and password:
                self.splunk_auth(username, password, totp_secret)
        else:
            self.is_authenticated = True

    def prepare_request(self, request):
        request.url = urljoin("https://%s:8089/" % self.address, request.url)
        return super(SplunkSession, self).prepare_request(request)

    def splunk_auth(self, username, password, totp_secret=None):
        # Try to authenticate w/ 2FA first
        if totp_secret:
            logger.info("Attempting to authenticate to %s with TOTP", self.address)
            totp = pyotp.TOTP(totp_secret, digits=8)
            try:
                r = self.post(
                    "/services/auth/login",
                    data={
                        "username": username,
                        "password": "%s,%s" % (password, totp.now()),
                        "cookie": "1"
                    }
                )
                r.raise_for_status()
            except Exception as e:
                # TOTP failed, probably a static password
                logger.warning("Unable to authenticate with TOTP (%s), trying single factor", str(e))
            else:
                # TOTP succeeded, no more auth required
                return

        r = self.post(
            "/services/auth/login",
            data={
                "username": username,
                "password": password,
                "cookie": "1"
            }
        )
        r.raise_for_status()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-H", "--host", required=True)
    ap.add_argument("-U", "--username", required=True)
    ap.add_argument("-P", "--password")
    ap.add_argument("--app", required=True)
    ap.add_argument("--proxy", action="append")
    ap.add_argument("--stanza", action="append")
    ap.add_argument("--totp-secret")

    ap.add_argument("conffile")
    args = ap.parse_args()


    try:
        session = SplunkSession(
            address=args.host,
            username=args.username,
            password=args.password or getpass.getpass("Password: "),
            totp_secret=args.totp_secret,
            proxies=args.proxy
        )
    except KeyboardInterrupt:
        sys.exit()


    conffile = args.conffile
    if conffile.endswith(".conf"):
        conffile = conffile[:-5]

    r = session.get(
        "/servicesNS/-/-/configs/conf-%s" % conffile,
        params={"count": 0}
    )
    r.raise_for_status()

    live_config_dict = {}
    for entry in r.json()["entry"]:
        if entry["content"]["eai:appName"] != args.app:
            continue
        elif args.stanza and entry["name"] not in args.stanza:
            continue

        content = {}
        for k in entry["content"]:
            if k == "eai" or k.startswith("eai:"):
                continue
            content[k] = entry["content"][k]
        live_config_dict.update({entry["name"]: content})

    live_config = configparser.RawConfigParser(
        delimiters="=",
        comment_prefixes="#"
    )
    live_config.optionxform = str
    live_config.read_dict(live_config_dict)

    tmp = tempfile.NamedTemporaryFile()
    with open(tmp.name, mode="w") as f:
        live_config.write(f)

    proc = subprocess.Popen("$EDITOR %s" % tmp.name, shell=True)
    proc.communicate()

    new_config = configparser.RawConfigParser(delimiters="=", comment_prefixes="#")
    new_config.optionxform = str
    new_config.read(tmp.name)

    all_sections = list(set(new_config.sections() + live_config.sections()))

    for section in all_sections:
        url_section = quote(section, safe="")

        if section in live_config and section in new_config:
            live_config_dict = {k: v for (k, v) in live_config[section].items()}
            new_config_dict = {k: v for (k, v) in new_config[section].items()}

            dirty = []
            all_keys = list(set(list(live_config_dict.keys()) + list(new_config_dict.keys())))
            for key in all_keys:
                if not (key in live_config_dict and key in new_config_dict):
                    dirty.append(key)
                elif live_config_dict[key] != new_config_dict[key]:
                    dirty.append(key)

            if dirty:
                print(dirty)
                r = session.post(
                    "/servicesNS/nobody/%s/configs/conf-%s/%s" % (args.app, conffile, url_section),
                    data=new_config_dict
                )
                r.raise_for_status()
        elif section in live_config:
            r = session.delete(
                "/servicesNS/nobody/%s/configs/conf-%s/%s" % (args.app, conffile, url_section),
                data={"name": section}
            )
            r.raise_for_status()
        elif section in new_config:
            new_config_dict = {k: v for (k, v) in new_config[section].items()}
            r = session.post(
                "/servicesNS/nobody/%s/configs/conf-%s/%s" % (args.app, conffile, url_section),
                data={"name": section}
            )
            r.raise_for_status()
            r = session.post(
                "/servicesNS/nobody/%s/configs/conf-%s/%s" % (args.app, conffile, url_section),
                data=new_config_dict
            )
            r.raise_for_status()


if __name__ == "__main__":
    main()
