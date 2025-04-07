import argparse
import asyncio
import datetime
import json
import logging
import os
import socket
import sys
import threading
import traceback
import uuid
from base64 import b64encode
from configparser import ConfigParser
from operator import itemgetter
from typing import Optional

import asyncssh
from asyncssh.misc import ConnectionLost
import geoip2.database

from langchain_core.chat_history import (
    BaseChatMessageHistory,
    InMemoryChatMessageHistory,
)
from langchain_core.messages import HumanMessage, SystemMessage, trim_messages
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnablePassthrough
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_openai import ChatOpenAI

from honeypot_server.command_classifier import analyze_command, classify_command
from honeypot_server.logging_util import log_event

global_command_database = []
geo_reader = geoip2.database.Reader("GeoLite2-City.mmdb")

def detect_anomaly(command, tokenizer, known_vocab):
    tokens = command.split()
    unknown_tokens = [word for word in tokens if word not in known_vocab]
    if len(unknown_tokens) > 3:  # Threshold
        return True
    return False

def get_location(ip_address):
    try:
        geo_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        response = geo_reader.city(ip_address)
        location_data = {
            "country": response.country.name,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
        }
        geo_reader.close()
        return location_data
    except Exception as e:
        print(f"GeoIP lookup failed: {e}")
        return None


class JSONFormatter(logging.Formatter):
    def __init__(self, sensor_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sensor_name = sensor_name

    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(
                record.created, datetime.timezone.utc
            ).isoformat(sep="T", timespec="milliseconds"),
            "level": record.levelname,
            "task_name": record.task_name,
            "src_ip": record.src_ip,
            "src_port": record.src_port,
            "dst_ip": record.dst_ip,
            "dst_port": record.dst_port,
            "message": record.getMessage(),
            "sensor_name": self.sensor_name,
            "sensor_protocol": "ssh",
        }
        if hasattr(record, "interactive"):
            log_record["interactive"] = record.interactive

        for key, value in record.__dict__.items():
            if key not in log_record and key != "args" and key != "msg":
                log_record[key] = value
        return json.dumps(log_record)


class MySSHServer(asyncssh.SSHServer):
    def __init__(self):
        super().__init__()
        self.summary_generated = False

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:

        peername = conn.get_extra_info("peername")
        sockname = conn.get_extra_info("sockname")

        if peername is not None:
            src_ip, src_port = peername[:2]
        else:
            src_ip, src_port = "-", "-"

        if sockname is not None:
            dst_ip, dst_port = sockname[:2]
        else:
            dst_ip, dst_port = "-", "-"

        thread_local.src_ip = src_ip
        thread_local.src_port = src_port
        thread_local.dst_ip = dst_ip
        thread_local.dst_port = dst_port

        location = get_location(src_ip)

        logger.info(
            "SSH connection received",
            extra={
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            },
        )
        print(f"🚨 New Attack from {location} (IP: {src_ip})")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.error("SSH connection error", extra={"error": str(exc)})
            if not isinstance(exc, ConnectionLost):
                traceback.print_exception(exc)
        else:
            logger.info("SSH connection closed")

        if (
            hasattr(self, "_process")
            and hasattr(self, "_llm_config")
            and hasattr(self, "_session")
        ):
            summary = session_summary(global_command_database)
            logger.info(summary)

    def begin_auth(self, username: str) -> bool:
        if accounts.get(username) != "":
            logger.info("User attempting to authenticate", extra={"username": username})
            return True
        else:
            logger.info(
                "Authentication success", extra={"username": username, "password": ""}
            )
            return False

    def password_auth_supported(self) -> bool:
        return True

    def host_based_auth_supported(self) -> bool:
        return False

    def public_key_auth_supported(self) -> bool:
        return False

    def kbdinit_auth_supported(self) -> bool:
        return False

    def validate_password(self, username: str, password: str) -> bool:
        pw = accounts.get(username, "*")

        if pw == "*" or (pw != "*" and password == pw):
            logger.info(
                "Authentication success",
                extra={"username": username, "password": password},
            )
            return True
        else:
            logger.info(
                "Authentication failed",
                extra={"username": username, "password": password},
            )
            return False


def session_summary(command_log):
    total = len(command_log)
    if total == 0:
        return "No commands issued."

    malicious = sum(1 for cmd in command_log if cmd["classification"] == "MALICIOUS")
    suspicious = sum(1 for cmd in command_log if cmd["classification"] == "SUSPICIOUS")
    benign = sum(1 for cmd in command_log if cmd["classification"] == "BENIGN")

    risk_score = (malicious + 0.5 * suspicious) / total * 100
    summary_text = (
        f"Session Summary: {total} total commands. "
        f"Benign: {benign}, Suspicious: {suspicious}, Malicious: {malicious}. "
        f"Risk Score: {risk_score:.1f}%"
    )
    return summary_text


def load_prompt():
    try:
        with open("config/prompt.txt", "r") as file:
            return file.read()
    except FileNotFoundError:
        logging.error("config/prompt.txt not found! Using default system prompt.")
        return "Simulate a realistic Linux system."


async def handle_client(
    process: asyncssh.SSHServerProcess, server: MySSHServer
) -> None:
    task_uuid = f"session-{uuid.uuid4()}"
    current_task = asyncio.current_task()
    current_task.set_name(task_uuid)

    llm_config = {"configurable": {"session_id": task_uuid}}
    command_log = []
    system_prompt = load_prompt()

    try:
        if process.command:
            command = process.command.strip()

            logger.info(
                "User input",
                extra={
                    "details": b64encode(command.encode("utf-8")).decode("utf-8"),
                    "interactive": False,
                },
            )

            prediction, is_anomaly = analyze_command(command)
            classification = classify_command(prediction)

            if is_anomaly:
                classification = "ANOMALOUS"

            cmd_entry = {"command": command, "classification": classification}
            command_log.append(cmd_entry)
            global_command_database.append(cmd_entry)
            logger.info(
                "Command Classified",
                extra={
                    "command": command,
                    "classification": classification,
                    "prediction": (
                        str(prediction.tolist()) if prediction is not None else "None"
                    ),
                },
            )

            try:
                ai_response = await with_message_history.ainvoke(
                    {
                        "messages": [
                            SystemMessage(content=system_prompt),
                            HumanMessage(content=command),
                        ],
                        "username": process.get_extra_info("username"),
                        "interactive": True,
                    },
                    config=llm_config,
                )

                if hasattr(ai_response, "content"):
                    process.stdout.write(f"{ai_response.content}\n")
                    logger.info("AI Response", extra={"details": ai_response.content})
                else:
                    logger.error("AI Response format incorrect.")
                    process.stdout.write("Command executed successfully.\n")

            except Exception as e:
                logger.error(f"Error generating AI response: {str(e)}")
                process.stdout.write("Command executed successfully.\n")

            await session_summary(command_log)
            process.exit(0)

        else:

            try:
                ai_welcome = await with_message_history.ainvoke(
                    {
                        "messages": [
                            SystemMessage(content=system_prompt),
                            HumanMessage(
                                content="Generate a realistic SSH welcome message following Linux system rules."
                            ),
                        ],
                        "username": process.get_extra_info("username"),
                        "interactive": True,
                    },
                    config=llm_config,
                )

                if hasattr(ai_welcome, "content"):
                    process.stdout.write(f"{ai_welcome.content}\n")
                else:
                    logger.error("AI Welcome message format incorrect.")
                    process.stdout.write("Welcome to the system!\n")

            except Exception as e:
                logger.error(f"Error generating welcome message: {str(e)}")
                process.stdout.write("Welcome to the system!\n")

            process.stdout.write("> ")
            await process.stdout.drain()

            async for line in process.stdin:
                command = line.strip()

                if not command:
                    process.stdout.write("> ")
                    await process.stdout.drain()
                    continue

                logger.info(
                    "User input",
                    extra={
                        "details": b64encode(command.encode("utf-8")).decode("utf-8"),
                        "interactive": True,
                    },
                )

                prediction, is_anomaly = analyze_command(command)
                classification = classify_command(prediction)

                if is_anomaly:
                    classification = "ANOMALOUS"

                cmd_entry = {"command": command, "classification": classification}
                command_log.append(cmd_entry)
                global_command_database.append(cmd_entry)
                # ✅ Immediately update session summary after the command
                summary_text = session_summary(command_log)
                logger.info("Session Summary", extra={"summary": summary_text})
                logger.info(
                    "Command Classified",
                    extra={
                        "command": command,
                        "classification": classification,
                        "prediction": (
                            str(prediction.tolist())
                            if prediction is not None
                            else "None"
                        ),
                    },
                )
                log_event(
                    "CommandClassified", command=command, classification=classification
                )

                try:
                    ai_response = await with_message_history.ainvoke(
                        {
                            "messages": [
                                SystemMessage(content=system_prompt),
                                HumanMessage(content=command),
                            ],
                            "username": process.get_extra_info("username"),
                            "interactive": True,
                        },
                        config=llm_config,
                    )

                    if hasattr(ai_response, "content"):
                        process.stdout.write(f"{ai_response.content}\n")
                    else:
                        logger.error("AI Response format incorrect.")
                        process.stdout.write("Command executed successfully.\n")

                except Exception as e:
                    logger.error(f"Error generating AI system response: {str(e)}")
                    process.stdout.write("Command executed successfully.\n")

                process.stdout.write("> ")
                await process.stdout.drain()

    except asyncssh.BreakReceived:
        pass

    finally:
        summary_text = session_summary(command_log)
        print(f"📊 Generated session summary:\n{summary_text}")

        logger.info("Session Summary", extra={"summary": summary_text})

        process.exit(0)

async def start_server() -> None:
    async def process_factory(process: asyncssh.SSHServerProcess) -> None:
        server = process.get_server()
        await handle_client(process, server)

    await asyncssh.listen(
        port=config["ssh"].getint("port", 8022),
        reuse_address=True,
        reuse_port=True,
        server_factory=MySSHServer,
        server_host_keys=config["ssh"].get("host_priv_key", "ssh_host_key"),
        process_factory=lambda process: handle_client(process, MySSHServer()),
        server_version=config["ssh"].get(
            "server_version_string", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
        ),
    )


class ContextFilter(logging.Filter):
    def filter(self, record):

        task = asyncio.current_task()
        if task:
            task_name = task.get_name()
        else:
            task_name = thread_local.__dict__.get("session_id", "-")

        record.src_ip = thread_local.__dict__.get("src_ip", "-")
        record.src_port = thread_local.__dict__.get("src_port", "-")
        record.dst_ip = thread_local.__dict__.get("dst_ip", "-")
        record.dst_port = thread_local.__dict__.get("dst_port", "-")

        record.task_name = task_name

        return True


llm_sessions = dict()


def llm_get_session_history(session_id: str) -> BaseChatMessageHistory:
    if session_id not in llm_sessions:
        llm_sessions[session_id] = InMemoryChatMessageHistory()
    return llm_sessions[session_id]


def get_user_accounts() -> dict:
    if (not "user_accounts" in config) or (len(config.items("user_accounts")) == 0):
        raise ValueError("No user accounts found in configuration file.")

    accounts = dict()

    for k, v in config.items("user_accounts"):
        accounts[k] = v

    return accounts


def choose_llm(llm_provider: Optional[str] = None, model_name: Optional[str] = None):
    llm_provider_name = llm_provider or config["llm"].get("llm_provider", "openai")
    llm_provider_name = llm_provider_name.lower()
    model_name = model_name or config["llm"].get("model_name", "gpt-3.5-turbo")

    if llm_provider_name == "openai":
        llm_model = ChatOpenAI(model=model_name)
    else:
        raise ValueError(f"Invalid LLM provider {llm_provider_name}.")

    return llm_model


def get_prompts(prompt: Optional[str], prompt_file: Optional[str]) -> dict:
    system_prompt = config["llm"]["system_prompt"]
    prompt_path = "config/prompt.txt"

    if not os.path.exists(prompt_path):
        print("Error: 'config/prompt.txt' is missing.", file=sys.stderr)
        sys.exit(1)

    with open(prompt_path, "r") as f:
        user_prompt = f.read()

    return {"system_prompt": system_prompt, "user_prompt": user_prompt}


try:

    parser = argparse.ArgumentParser(description="Start the SSH honeypot server.")
    parser.add_argument(
        "-c", "--config", type=str, default=None, help="Path to the configuration file"
    )
    parser.add_argument(
        "-p", "--prompt", type=str, help="The entire text of the prompt"
    )
    parser.add_argument(
        "-f",
        "--prompt-file",
        type=str,
        default="prompt.txt",
        help="Path to the prompt file",
    )
    parser.add_argument(
        "-l", "--llm-provider", type=str, help="The LLM provider to use"
    )
    parser.add_argument("-m", "--model-name", type=str, help="The model name to use")
    parser.add_argument(
        "-t",
        "--trimmer-max-tokens",
        type=int,
        help="The maximum number of tokens to send to the LLM backend in a single request",
    )
    parser.add_argument(
        "-s", "--system-prompt", type=str, help="System prompt for the LLM"
    )
    parser.add_argument(
        "-P", "--port", type=int, help="The port the SSH honeypot will listen on"
    )
    parser.add_argument(
        "-k", "--host-priv-key", type=str, help="The host key to use for the SSH server"
    )
    parser.add_argument(
        "-v",
        "--server-version-string",
        type=str,
        help="The server version string to send to clients",
    )
    parser.add_argument(
        "-L",
        "--log-file",
        type=str,
        help="The name of the file you wish to write the honeypot log to",
    )
    parser.add_argument(
        "-S",
        "--sensor-name",
        type=str,
        help="The name of the sensor, used to identify this honeypot in the logs",
    )
    parser.add_argument(
        "-u",
        "--user-account",
        action="append",
        help="User account in the form username=password. Can be repeated.",
    )
    args = parser.parse_args()

    config = ConfigParser()

    config_path = "config/config.ini"

    if args.config:
        config_path = args.config

    if not os.path.exists(config_path):
        print(
            f"❌ Error: The config file '{config_path}' does not exist.",
            file=sys.stderr,
        )
        sys.exit(1)

    config.read(config_path)

    if args.llm_provider:
        config["llm"]["llm_provider"] = args.llm_provider
    if args.model_name:
        config["llm"]["model_name"] = args.model_name
    if args.trimmer_max_tokens:
        config["llm"]["trimmer_max_tokens"] = str(args.trimmer_max_tokens)
    if args.system_prompt:
        config["llm"]["system_prompt"] = args.system_prompt
    if args.port:
        config["ssh"]["port"] = str(args.port)
    if args.host_priv_key:
        config["ssh"]["host_priv_key"] = args.host_priv_key
    if args.server_version_string:
        config["ssh"]["server_version_string"] = args.server_version_string
    if args.log_file:
        config["honeypot"]["log_file"] = args.log_file
    if args.sensor_name:
        config["honeypot"]["sensor_name"] = args.sensor_name

    if args.user_account:
        if "user_accounts" not in config:
            config["user_accounts"] = {}
        for account in args.user_account:
            if "=" in account:
                key, value = account.split("=", 1)
                config["user_accounts"][key.strip()] = value.strip()
            else:
                config["user_accounts"][account.strip()] = ""

    accounts = get_user_accounts()

    logging.Formatter.formatTime = (
        lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(
            record.created, datetime.timezone.utc
        ).isoformat(sep="T", timespec="milliseconds")
    )

    sensor_name = config["honeypot"].get("sensor_name", socket.gethostname())

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    log_file_handler = logging.FileHandler(
        config["honeypot"].get("log_file", "ssh_log.log")
    )
    logger.addHandler(log_file_handler)

    log_file_handler.setFormatter(JSONFormatter(sensor_name))

    f = ContextFilter()
    logger.addFilter(f)

    prompts = get_prompts(args.prompt, args.prompt_file)
    llm_system_prompt = prompts["system_prompt"]
    llm_user_prompt = prompts["user_prompt"]

    llm = choose_llm(config["llm"].get("llm_provider"), config["llm"].get("model_name"))

    llm_trimmer = trim_messages(
        max_tokens=config["llm"].getint("trimmer_max_tokens", 64000),
        strategy="last",
        token_counter=llm,
        include_system=True,
        allow_partial=False,
        start_on="human",
    )

    llm_prompt = ChatPromptTemplate.from_messages(
        [
            ("system", llm_system_prompt),
            ("system", llm_user_prompt),
            MessagesPlaceholder(variable_name="messages"),
        ]
    )
    llm_chain = (
        RunnablePassthrough.assign(messages=itemgetter("messages") | llm_trimmer)
        | llm_prompt
        | llm
    )
    with_message_history = RunnableWithMessageHistory(
        llm_chain, llm_get_session_history, input_messages_key="messages"
    )
    thread_local = threading.local()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_server())
    loop.run_forever()

except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)