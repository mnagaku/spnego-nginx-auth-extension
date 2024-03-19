import json
import os
import re

import gssapi
from flask import Flask, make_response, request
from ldap3 import KERBEROS, SASL, Connection, Server
from ldap3.utils.conv import escape_filter_chars

app = Flask(__name__)


def check_env_variables():
    """Check if all required environment variables are set."""
    required_vars = [
        "AD_SERVER",
        "CONFIG_PATH",
        "KEYTAB_PATH",
        "LDAP_SEARCH_BASE",
        "SERVER_PRINCIPAL_NAME",
    ]
    for var in required_vars:
        if not os.getenv(var):
            raise EnvironmentError(f"Required environment variable {var} is not set")


check_env_variables()


def load_acl(path_to_config):
    """Load ACL config file."""
    with open(path_to_config, "r") as config:
        return json.load(config)


acl = load_acl(os.getenv("CONFIG_PATH"))


def get_entry(uri, port):
    if port not in acl:
        return None
    longest_match = None
    max_length = 0
    for k, v in acl[port].items():
        if uri.startswith(k) and len(k) > max_length:
            longest_match = v
            max_length = len(k)
    return longest_match


def get_authorized_usernames(uri, port):
    """Return list of usernames for given uri."""
    entry = get_entry(uri, port)
    return entry.get("users", []) if entry else []


def get_authorized_group_dns(uri, port):
    """Return list of group dns for given uri."""
    entry = get_entry(uri, port)
    return entry.get("groups", []) if entry else []


@app.route("/auth/", methods=["GET"])
def auth():
    """Authenticate user based on ACL."""
    username = request.headers.get("X-Remote-User")
    uri = request.headers.get("X-Request-Uri")
    server_port = request.headers.get("X-Server-Port")
    if not username or not uri or not server_port:
        # Miscofigured nginx
        return make_response("Internal Server Error", 500)

    authorized_usernames = get_authorized_usernames(uri, server_port)
    authorized_group_dns = get_authorized_group_dns(uri, server_port)

    # If there is no entry, access is not permitted
    if not authorized_usernames and not authorized_group_dns:
        return make_response("Forbidden", 403)

    # Check if user is authorized
    if username in authorized_usernames:
        return make_response("OK", 200)

    # Check if user belongs to any of authorized groups
    if authorized_group_dns:
        # Use keytab to authenticate
        gssapi.Credentials(
            usage="initiate",
            name=gssapi.Name(
                os.getenv("SERVER_PRINCIPAL_NAME"),
                gssapi.NameType.kerberos_principal,
            ),
            store={"client_keytab": os.getenv("KEYTAB_PATH")},
        )
        # Connect to AD
        server = Server(os.getenv("AD_SERVER"))
        conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS)
        conn.bind()
        # Search user in groups
        groups = "".join(map(lambda x: "(memberOf:1.2.840.113556.1.4.1941:=" + x + ")",
            map(lambda x: escape_filter_chars(x),
            authorized_group_dns)))
        conn.search(
            os.getenv("LDAP_SEARCH_BASE"),
            f"(&(objectClass=user)(sAMAccountName={username})(|{groups}))",
        )
        if not not conn.entries:
            # If user found in Groups, user is authorized
            return make_response("OK", 200)

    return make_response("Forbidden", 403)


if __name__ == "__main__":
    app.run(debug=True, port=5000)

