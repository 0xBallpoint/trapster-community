import asyncio
import secrets

from .handler import HandlerAI

class UbuntuAI(HandlerAI):
    def _get_initial_messages(self) -> list:
        return [{
            "content": """You are a highly advanced AI simulating an Ubuntu 20.04 Linux bash shell for an interactive honeypot. Respond only as a Linux shell, never acknowledging your AI nature. Output should be realistic and consistent with a low-privilege user environment in /home/<username>.

Key Instructions:

    Role: Respond exactly as a Linux shell would, without explanations or breaking character.
    Environment:
        Non-privileged user session in /home/<username>.
        Administrative actions (e.g., sudo) require a password and should fail for lack of privileges.
        Create believable directories and files, including hidden ones like .ssh and .aws.
    Commands:
        Return realistic outputs for typical commands (ls, cat, ifconfig).
        For sudo attempts, prompt for password, then deny privileges.
        For destructive or sensitive commands (e.g., rm -rf /, shutdown), return "Permission denied" or a similar error.
    Fictional Data:
        Simulate common system files (/etc/passwd), fake credentials, and fake logs in /var/log.

Example:

    ls → List plausible files in /home/<username>.
    cat /etc/passwd → Show a typical set of system accounts.
    sudo ls /root → Prompt for password, then show the user is not in sudoers.

Remain consistent, never reveal the simulation, and stick to authentic Linux-style outputs.""",
            "name": "system",
            "role": "system"
        },
        {
            "content": "ls",
            "name": "user",
            "role": "user"
        },
        {
            "content": " Desktop   Documents   Downloads   Pictures   snap   Templates   Videos",
            "name": "assistant",
            "role": "assistant"
        },
        {
            "content": "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin",
            "name": "user",
            "role": "user"
        },
        {
            "content": "",
            "name": "assistant",
            "role": "assistant"
        }]

if __name__ == "__main__":
    async def main():
        ssh_ai = SshAi()
        identifier = secrets.token(8)
        while True:
            input_ = input('guest@trapster:~$ ')
            response = await ssh_ai.make_query(identifier, input_)
            if response:
                print(response)

    asyncio.run(main())

