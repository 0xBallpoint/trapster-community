<p align="right">
  <img src="https://github.com/user-attachments/assets/8b658484-c2ea-4c52-86b5-fe346dc37622" width="25%">
</p>

# Trapster Community
![License](https://img.shields.io/badge/license-AGPLv3+-blue)
![Python](https://img.shields.io/badge/python-3.11-blue)
![Status](https://img.shields.io/badge/status-Production/Stable-green)

Trapster Community is a low-interaction honeypot designed to be deployed on internal networks. It is built to monitor and detect suspicious activities, providing a deceptive layer to network security.

Visit the [Trapster website](https://trapster.cloud) to learn more about our commercial product, which includes advanced features like pre-configured hardened OS, automatic deployment, webhook, SIEM integration and much more...

## Features

- **Deceptive Security**: Mimics network services to lure and detect potential intruders.
- **Asynchronous Framework**: Utilizes Python's `asyncio` for efficient, non-blocking operations.
- **Configuration Management**: Easily configurable through `trapster.conf`.
- **Expandable Services**: Add and configure as many services as needed with minimal effort.
- **HTTP Honeypot Engine with AI capabilities**: Clone any website using YAML configuration, and use AI to generate responses to some HTTP requests.

## Supported Protocols

| Protocol | Notes |
|----------|-------------|
| DNS | Works as a proxy to a real DNS server |
| HTTP/HTTPS | Features custom YAML configuration templating engine |
| FTP | Capture FTP login attempts |
| LDAP | Capture LDAP login attempts |
| MSSQL | Capture MSSQL login attempts |
| POSTGRES | Capture POSTGRES login attempts |
| RDP | Capture RDP login attempts |
| SNMP | Capture SNMP login attempts |
| SSH | Capture SSH login attempts |
| TELNET | Capture Telnet login attempts |
| VNC | Capture VNC login attempts |
| RSYNC | Capture RSYNC login attempts |


## Documentation and installation guide

https://docs.trapster.cloud/community/


## Logs

### Format
Each module can generate up to four types of logs: `connection`, `data`, `login`, and `query`.
* `connection`: Indicates that a connection has been made to the module.
* `data`: Represents raw data that has been sent, logged in HEX format. This data is unprocessed.
* `login`: Captures login attempts to the module. The data field is in JSON format and contains processed information.
* `query`: Logs data that has been processed and does not correspond to an authentication attempt. The data field is in JSON format and contains processed information.


## HTTP Engine with AI capabilities

The HTTP module can emulate any website. It works with YAML configuration files to match requests using regular expressions, and can generate responses using either a template or an AI model.

The configuration are stored in [trapster/data/http](trapster/data/http), each folder represent a website.
An example of the functionnalities can be found at [trapster/data/http/demo_api/config.yaml](trapster/data/http/demo_api/config.yaml)

**Structure:**
- config.yaml: contains the configuration for the website.
- files/: contains the static files for the website.
- templates/: contains the templates for the website, it supports [jinja2](https://jinja.palletsprojects.com/en/3.1.x/) syntax.

### AI ALPHA support
To generate responses, you can use the `ai` field in the configuration. For now, it uses [OVHCloud AI Endpoints](https://endpoints.ai.cloud.ovh.net/) as it is still free, and in alpha.
The file `trapster/modules/libs/ai.py` contains the code to generate responses using the AI model. It is still very basic, and will be improved in the near future.

For example, this image show a request to capture SQLi attempts, and the response generated by the AI model.

<img src="images/sqli_ai_response_1.png" width="60%">

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (git checkout -b feature-branch).
3. Make your changes.
4. Commit your changes (git commit -m 'Add new feature').
5. Push to the branch (git push origin feature-branch).
6. Create a pull request.

## License

Trapster is licensed under the GNU Affero General Public License v3 or later (AGPLv3+). See the LICENSE file for more details.

