#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
from pathlib import Path

DOMAIN = "trusted.domain"
DEFAULT_OPENBAO_URL = "http://127.0.0.1:8200"
DEFAULT_KV_MOUNT = "secret"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate baseline docker harness workspace")
    parser.add_argument("--scenario-file", required=True)
    parser.add_argument("--artifact-dir", required=True)
    return parser.parse_args()


def build_agent_toml(service_name: str, hostname: str, instance_id: str) -> str:
    return (
        "[acme]\n"
        'http_responder_hmac = "seed-responder-hmac"\n\n'
        "[trust]\n"
        'trusted_ca_sha256 = ["' + ("0" * 64) + '"]\n\n'
        "[[profiles]]\n"
        f'service_name = "{service_name}"\n'
        f'instance_id = "{instance_id}"\n'
        f'hostname = "{hostname}"\n\n'
        "[profiles.paths]\n"
        f'cert = "certs/{service_name}.crt"\n'
        f'key = "certs/{service_name}.key"\n'
    )


def ensure_cert_pair(work_dir: Path, service_name: str, hostname: str, instance_id: str) -> None:
    cert_path = work_dir / "certs" / f"{service_name}.crt"
    key_path = work_dir / "certs" / f"{service_name}.key"
    dns_name = f"{instance_id}.{service_name}.{hostname}.{DOMAIN}"
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-nodes",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        "1",
        "-subj",
        f"/CN={dns_name}",
        "-addext",
        f"subjectAltName=DNS:{dns_name}",
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chmod(cert_path, 0o600)
    os.chmod(key_path, 0o600)


def write_bootroot_agent_stub(node_bin_dir: Path) -> None:
    node_bin_dir.mkdir(parents=True, exist_ok=True)
    stub = node_bin_dir / "bootroot-agent"
    stub.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
    os.chmod(stub, 0o700)


def main() -> None:
    args = parse_args()
    scenario_file = Path(args.scenario_file)
    artifact_dir = Path(args.artifact_dir).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)

    scenario = json.loads(scenario_file.read_text(encoding="utf-8"))
    layout = {
        "scenario_id": scenario["id"],
        "nodes": [],
        "services": [],
    }

    for node in scenario["nodes"]:
        node_id = node["id"]
        hostname = node_id
        work_dir = artifact_dir / "nodes" / node_id
        (work_dir / "certs").mkdir(parents=True, exist_ok=True)
        (work_dir / "configs").mkdir(parents=True, exist_ok=True)

        state_services = {}
        layout_node = {
            "node_id": node_id,
            "work_dir": str(work_dir),
            "services": [],
        }

        for service in node["services"]:
            service_name = service["service_name"]
            deploy_type = service["deploy_type"]
            instance_id = service["instance_id"]
            container_name = service.get("container_name")

            secret_dir = work_dir / "secrets" / "services" / service_name
            secret_dir.mkdir(parents=True, exist_ok=True)

            role_id_path = secret_dir / "role_id"
            secret_id_path = secret_dir / "secret_id"
            eab_file_path = secret_dir / "eab.json"
            agent_config_path = work_dir / "configs" / f"{service_name}.toml"
            ca_bundle_path = work_dir / "certs" / f"{service_name}-ca-bundle.pem"
            summary_json_path = work_dir / "summaries" / f"{service_name}.json"
            summary_json_path.parent.mkdir(parents=True, exist_ok=True)

            role_id_path.write_text(f"role-{service_name}\n", encoding="utf-8")
            secret_id_path.write_text(f"seed-secret-{service_name}\n", encoding="utf-8")
            eab_file_path.write_text(
                json.dumps(
                    {"kid": f"seed-kid-{service_name}", "hmac": f"seed-hmac-{service_name}"}
                ),
                encoding="utf-8",
            )
            os.chmod(role_id_path, 0o600)
            os.chmod(secret_id_path, 0o600)
            os.chmod(eab_file_path, 0o600)

            agent_config_path.write_text(
                build_agent_toml(service_name, hostname, instance_id),
                encoding="utf-8",
            )
            os.chmod(agent_config_path, 0o600)

            ensure_cert_pair(work_dir, service_name, hostname, instance_id)

            state_services[service_name] = {
                "service_name": service_name,
                "deploy_type": deploy_type,
                "delivery_mode": "remote-bootstrap",
                "sync_status": {
                    "secret_id": "pending",
                    "eab": "pending",
                    "responder_hmac": "pending",
                    "trust_sync": "pending",
                },
                "hostname": hostname,
                "domain": DOMAIN,
                "agent_config_path": f"configs/{service_name}.toml",
                "cert_path": f"certs/{service_name}.crt",
                "key_path": f"certs/{service_name}.key",
                "instance_id": instance_id,
                "container_name": container_name,
                "notes": None,
                "approle": {
                    "role_name": f"bootroot-service-{service_name}",
                    "role_id": f"role-{service_name}",
                    "secret_id_path": f"secrets/services/{service_name}/secret_id",
                    "policy_name": f"bootroot-service-{service_name}",
                },
            }

            layout_entry = {
                "node_id": node_id,
                "service_name": service_name,
                "deploy_type": deploy_type,
                "instance_id": instance_id,
                "container_name": container_name,
                "work_dir": str(work_dir),
                "state_path": str(work_dir / "state.json"),
                "role_id_path": str(role_id_path),
                "secret_id_path": str(secret_id_path),
                "eab_file_path": str(eab_file_path),
                "agent_config_path": str(agent_config_path),
                "ca_bundle_path": str(ca_bundle_path),
                "summary_json_path": str(summary_json_path),
            }
            layout["services"].append(layout_entry)
            layout_node["services"].append(layout_entry)

        state_payload = {
            "openbao_url": DEFAULT_OPENBAO_URL,
            "kv_mount": DEFAULT_KV_MOUNT,
            "secrets_dir": "secrets",
            "policies": {},
            "approles": {},
            "services": state_services,
        }
        (work_dir / "state.json").write_text(
            json.dumps(state_payload, indent=2),
            encoding="utf-8",
        )
        write_bootroot_agent_stub(work_dir / "bin")
        layout["nodes"].append(layout_node)

    (artifact_dir / "layout.json").write_text(json.dumps(layout, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
