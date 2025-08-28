<p align="right">
  <a href="https://trapster.cloud">
    <img src="https://github.com/user-attachments/assets/8b658484-c2ea-4c52-86b5-fe346dc37622" width="25%" alt="Trapster logo" />
  </a>
</p>



<h2 align="center" >Trapster Community </h2>
<p align="center"><a href="https://trapster.cloud/">🌐 Website</a> · <a href="https://docs.trapster.cloud/">📚 Documentation</a> · <a href="https://discord.gg/nNJv8Hj5EE">💬 Discord</a></p>
<br />

Trapster Community is a low-interaction honeypot designed to be deployed on internal networks or to capture credentials. It is built to monitor and detect suspicious activities, providing a deceptive layer to network security.

Visit the [Trapster website](https://trapster.cloud) to learn more about our commercial version, which includes advanced features like pre-configured hardened OS, automatic deployment, webhook, SIEM integration and much more...

## Features

- **Deceptive Security**: Mimics network services to lure and detect potential intruders.
- **Asynchronous Framework**: Utilizes Python's `asyncio` for efficient, non-blocking operations.
- **Configuration Management**: Easily configurable through `trapster.conf`.
- **Expandable Services**: Add and configure as many services as needed with minimal effort.
- **HTTP Honeypot Engine with AI capabilities**: Clone any website using YAML configuration, and use AI to generate responses to some HTTP requests.

## Supported Protocols

| Protocol | Notes |
|----------|-------------|
| FTP (21) | Capture FTP login attempts |
| SSH (22) | Capture SSH login attempts |
| Telnet (23) | Capture TELNET login attempts |
| DNS (53) | Works as a proxy to a real DNS server, and log queries |
| HTTP/HTTPS (80/443) | Copy website, features custom YAML configuration templating engine |
| SNMP (161) | Log SNMP queries |
| LDAP (389) | Capture LDAP login attempts and queries |
| Rsync (873) | Capture RSYNC login attempts |
| MSSQL (1433) | Capture MSSQL login attempts |
| MySQL (3306) | Capture MySQL login attempts |
| RDP (3389) | Capture RDP login attempts |
| PostgreSQL (5432) | Capture POSTGRES login attempts |
| VNC (5900) | Capture VNC login attempts |

## Documentation and installation guide

https://docs.trapster.cloud/community/

## Quick start
Quick start with a demo configuration file:
```bash
git clone https://github.com/0xBallpoint/trapster-community
cd trapster-community
docker compose up --build
```
For a quick start with AI responses for HTTP (port 8081), just add a `.env` file, and run `docker compose up` again:
```
AI_MODEL=o4-mini
AI_BASE_URL=https://api.openai.com/v1/
AI_API_KEY=<YOUR_OPENAI_API_KEY>
```

## Logs

### Format
Each module can generate up to 4 types of logs: `connection`, `data`, `login`, and `query`.
* `connection`: Indicates that a connection has been made to the module.
* `data`: Represents raw data that has been sent, logged in HEX format. This data is unprocessed.
* `login`: Captures login attempts to the module. The data field is in JSON format and contains processed information.
* `query`: Logs data that has been processed and does not correspond to an authentication attempt. The data field is in JSON format and contains processed information.

You can then filter log type you don't need.

## HTTP Engine

### Configuration
The HTTP module can emulate any website. It works with YAML configuration files to match requests using regular expressions, and can generate responses using either a template or an AI model.

The configuration are stored in [trapster/data/http](trapster/data/http), each folder represent a website.
An example of the functionnalities can be found at [trapster/data/http/demo_api/config.yaml](trapster/data/http/demo_api/config.yaml)

**Structure:**
- config.yaml: contains the configuration for the website.
- files/: contains the static files for the website.
- templates/: contains the templates for the website, it supports [jinja2](https://jinja.palletsprojects.com/en/3.1.x/) syntax.

Documentation : https://docs.trapster.cloud/community/modules/web/

### Example: Fortigate

The default HTTPS server shows a fortigate login page:
![image](https://github.com/user-attachments/assets/5b351089-c7b9-471b-ac33-fcc79454e73c)

If someone tries to login, you will get a log like this one:
```json
{
   "device":"trapster-1",
   "logtype":"https.login",
   "dst_ip":"127.0.0.1",
   "dst_port":8443,
   "src_ip":"127.0.0.1",
   "src_port":45182,
   "timestamp":"2025-02-28 18:53:18.498008",
   "data":"616a61783d3126757365726e616d653d61646d696e267365637265746b65793d61646d696e2672656469723d253246",
   "extra":{
      "method":"POST",
      "target":"/logincheck",
      "headers":{
         "host":"127.0.0.1:8443",
         "connection":"keep-alive",
         "content-length":"47",
         "cache-control":"no-store, no-cache, must-revalidate",
         "sec-ch-ua-platform":"\"Linux\"",
         "pragma":"no-cache",
         "sec-ch-ua":"\"Not(A:Brand\";v=\"99\", \"Google Chrome\";v=\"133\", \"Chromium\";v=\"133\"",
         "sec-ch-ua-mobile":"?0",
         "user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.3",
         "if-modified-since":"Sat, 1 Jan 2000 00:00:00 GMT",
         "content-type":"text/plain;charset=UTF-8",
         "accept":"*/*",
         "origin":"https://127.0.0.1:8443",
         "sec-fetch-site":"same-origin",
         "sec-fetch-mode":"cors",
         "sec-fetch-dest":"empty",
         "referer":"https://127.0.0.1:8443/login?redir=%2F",
         "accept-encoding":"gzip, deflate, br, zstd",
         "accept-language":"en-US,en;q=0.9"
      },
      "status_code":200,
      "username":"admin",
      "password":"admin"
   }
}
```

## AI support

To use AI, install the dependencies:
```bash
pip install trapster[ai]

# or locally
python3 -m pip install ".[ai]" 
```
Then, you need to set your environnement variables. First, copy the `example.env` file
```bash
cp example.env .env
```
Now, you can set:
```
AI_MODEL=
AI_BASE_URL=
AI_API_KEY=
AI_MEMORY_ENABLE=false
# AI_MEMORY_PATH=
```
AI_MEMORY_ENABLE and AI_MEMORY_PATH are optionnal, it allows you to set persistant data between session using a database. Sessions are based on the IP of the user, and the username. 
By default, if you set `AI_MEMORY_ENABLE=true`, then the database will be in `trapster/data/ai_memory.db`

You can also use `OPENAI_API_KEY` directly if you want to use the default `o4-mini` model:
```bash
export OPENAI_API_KEY=... && venv/bin/python3 main.py
```

### AI for SSH
Trapster can generate fake shell responses when user connect to SSH.

To enable AI for SSH, allow the users to connect with username/password combination that you can define in the configuration file `trapster.conf` like :
```
...
 "ssh": [
      {
        "port": 2222,
        "version": "SSH-2.0-OpenSSH_8.1p1 Debian-1",
        "banner": null,
        "users": {
		      "guest":"guest",
            "admin":"admin",
            "ubuntu":"ubuntu",
            "pi":"raspberry",
            "debian":"password"
        }
      }
...
```

### AI for HTTP
To generate responses, you can use the `ai` field in the configuration. It will generate a response for the corresponding URL. You can change the prompt for each URL. This enable to fast, pre-determined responses for the honeypot website, and only AI responses when the URL is unkown.
For example, this image show a request to capture SQLi attempts. Only the SQLi attempts are generated by AI.

<img src="images/sqli_ai_response_1.png" width="60%">

A full example is available in `trapster/data/demo_ai`

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

