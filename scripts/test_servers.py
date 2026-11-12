"""
This is a script to spin up docker containers that host a QUIC server and run hephaestus against
them.


Important Notes:
    - This script should be independent of the current working directory, but it does depend on the
      location of the python file itself, so don't move it (or change the script).
    - This script also assumes certain folder names and locations match the upstream version.
      Therefore, do not change these or the script won't work. I did this so that these
      paths do not have to be passed in as arguments.
"""
from __future__ import annotations
from pathlib import Path
import subprocess
from typing import Optional
import docker
import time
import pyshark
from multiprocessing import Process
import os

def LOG(msg, tag="LOG"):
    print(f"[{tag}] {msg}")

# This finds the correct path if and only if this script hasn't moved and nothing was done to the
# default cargo build location, i.e. CRATE_ROOT/target/...

# This is the top-level folder of the repository.
ROOT_PATH = Path(__file__).resolve().parent.parent
HEPHAESTUS_BIN_REL_PATH = Path("./target/release/hephaestus")
# Location of the hephaestus executable.
HEPHAESTUS_BIN_PATH = (ROOT_PATH / HEPHAESTUS_BIN_REL_PATH).resolve()
OUTPUT_DIR = ROOT_PATH / "captures"


# Have path, check if cargo build was run. If not ask to run it.
if not HEPHAESTUS_BIN_PATH.exists():
    ans = input("Executable not found, please run cargo build --relase")
    exit(-1)

# At this point, we know we have a binary.
# Now we instantiate a docker client.

docker_client = docker.from_env()

# Some static variables
NETWORK_NAME = "quic_endpoint"
SERVER_PORT = 5555
SERVER_IP = "172.27.0.3"

networks = docker_client.networks.list(names=[NETWORK_NAME])

if not networks:
    # Create docker network if it doesn't exist.
    # This is not nice, but for now it suffices.
    ip_pool = docker.types.IPAMPool(subnet="172.27.0.0/24", iprange=None, gateway="172.27.0.1")
    ipam_config = docker.types.IPAMConfig(driver="default", pool_configs=[ip_pool])
    network = docker_client.networks.create(NETWORK_NAME, driver="bridge", ipam=ipam_config, check_duplicate=True)
else:
    network = networks[0]

# We need to run multiple docker commands:
#   1. Build the image.
#   2. Configure the network.
#   3. Run the container.
#   4. Stop the container.
# docker network create -d bridge -d default --subnet 172.27.0.0/24 --gateway 172.27.0.1 endpoint
# docker run --net endpoint --ip 172.27.0.3 --name server-name --restart unless-stopped \
#            --security-opt no-new-privileges -p 5555:5555/udp --tmpfs /var/run,/var/cache,/tmp 

def run_from_dockerfile(context: Path, server_name: str, verbose=True) -> docker.models.containers.Container:
    # Build the image
    image, logs = docker_client.images.build(path=str(context))

    if verbose:
        for log_entry in logs:
            if "stream" in log_entry:
                LOG(log_entry["stream"].strip(), "DOCKER")
            else:
                LOG(log_entry, "DOCKER")

    networking_config = {
        NETWORK_NAME: docker_client.api.create_endpoint_config(
            ipv4_address=SERVER_IP,
        )
    }

    port_config = {
        f"{SERVER_PORT}/udp": SERVER_PORT,
    }

    security_opts = ["no-new-privileges"]

    container = docker_client.containers.run(image, [], name=server_name, network=NETWORK_NAME, networking_config=None, ports=port_config, detach=True, security_opt=security_opts)

    return container

def run_from_image(image_name: str, server_name: str):
    pass

# Next we take stock of the available servers.
# We parse them into a rather simple Server class to avoid clutter.


class Server:
    def __init__(self, name, path):
        self.name = name
        self.path = path

    def attack(self, verbose=True) -> dict:
        """Run hephaestus on this server. Performs the following steps:

        1. Launch the container.
        2. Run hephaestus.
        3. Collect network traces with tshark.
        4. Save network traces.
        5. Return path and hephaestus return code.
        """

        # Start up the server.
        server_container = run_from_dockerfile(self.path, self.name)

        print(server_container, flush=True)

        # Start sniffing
        def sniff():
            out_file = OUTPUT_DIR / f"{self.name}.json"
            capture = pyshark.LiveCapture(interface="any", display_filter="udp.port==5555", use_ek=True)
            capture.sniff(timeout=15)

            num_packets = len(capture)
            packets = [capture[i] for i in range(num_packets)]


        p = Process(target=sniff)
        p.start()

        time.sleep(1)

        hephaestus_command = [
            str(HEPHAESTUS_BIN_PATH), 
            "--victim-addr", f"127.0.0.1:{SERVER_PORT}",
            "--target-addr", "127.0.0.1:1234",
            "vnrf",
            "--dcid", "A" * 20,
            "--scid", "B" * 20
        ]

        hephaestus_command_cmrf = [
            str(HEPHAESTUS_BIN_PATH), 
            "--victim-addr", f"127.0.0.1:{SERVER_PORT}",
            "--target-addr", "127.0.0.1:1234",
            "cmrf",
            "--scid", "B" * 20
        ]



        LOG("Launching attack.")
        print(" ".join(hephaestus_command_cmrf))
        LOG(f"Attack command: {hephaestus_command}")
        result = subprocess.run(hephaestus_command_cmrf)

        # Clean up
        server_container.stop()
        # Frees up the name again.
        server_container.remove()

        p.join()


        return dict()

    @classmethod
    def from_path(cls, server_dir: Path) -> Optional[Server]:
        dockerfile = server_dir / "Dockerfile"
        if not dockerfile.exists():
            LOG(f"No dockerfile for server: {server_dir}. Skipping.")
            return None

        return Server(server_dir.stem, server_dir)

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return str(self)
        


SERVER_BASE_PATH = (ROOT_PATH / "./servers/").resolve()

if not SERVER_BASE_PATH.exists():
    LOG(f"Server path ({SERVER_BASE_PATH}) does not exist, exiting.")
    exit(-1)

server_list = [Server.from_path(server) for server in SERVER_BASE_PATH.iterdir() 
                                                if server.is_dir()]
# Get rid of skipped servers.
server_list = [server for server in server_list if server]

for server in server_list:
    if server.name == "quinn":
        server.attack()

