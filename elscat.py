#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import glob
import random
import string
from getpass import getuser

def run_command(cmd, check=True):
    result = subprocess.run(cmd, shell=True, text=True)
    if check and result.returncode != 0:
        print(f"Command failed: {cmd}")
        sys.exit(1)
    return result

def check_environment():
    # Check if running as root
    if getuser() != 'root':
        print("Please run this script with sudo or as root")
        sys.exit(1)
    
    # Check Debian version
    with open("/etc/os-release") as f:
        if "Debian GNU/Linux 12" not in f.read():
            print("This script requires Debian 12")
            sys.exit(1)

def install_java():
    print("\nInstalling Java...")
    run_command("apt-get update -qq")
    run_command("apt-get install -y openjdk-17-jdk-headless")

def install_elasticsearch():
    print("\nInstalling Elasticsearch...")
    # Add Elasticsearch repository
    run_command("wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg")
    run_command('echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list')
    
    run_command("apt-get update -qq")
    run_command("apt-get install -y elasticsearch")
    
    # Configure JVM heap size
    heap_size = input("\nEnter Elasticsearch JVM heap size (e.g., 1g, leave empty for default): ") or "1g"
    jvm_options = f"-Xms{heap_size}\n-Xmx{heap_size}\n"
    run_command("mkdir -p /etc/elasticsearch/jvm.options.d/")
    with open("/etc/elasticsearch/jvm.options.d/heap.options", "w") as f:
        f.write(jvm_options)
    
    # Configure Elasticsearch
    with open("/etc/elasticsearch/elasticsearch.yml", "a") as f:
        f.write("discovery.type: single-node\n")
        f.write("network.host: 0.0.0.0\n")
    
    # Start Elasticsearch
    run_command("systemctl daemon-reload")
    run_command("systemctl enable elasticsearch")
    run_command("systemctl start elasticsearch")

def get_elastic_password():
    print("\nWaiting for Elasticsearch to start...")
    time.sleep(30  # Wait for Elasticsearch to initialize
    
    # Find password in logs
    log_files = glob.glob("/var/log/elasticsearch/*.log")
    for log_file in log_files:
        with open(log_file, "r") as f:
            for line in f:
                if "Password for the elastic user" in line:
                    return line.split(": ")[-1].strip()
    return None

def install_tracecat(es_password):
    print("\nInstalling Tracecat...")
    # Create system user
    run_command("useradd -r -s /usr/sbin/nologin tracecat")
    
    # Install Tracecat
    run_command("apt-get install -y python3-pip python3-venv")
    run_command("mkdir -p /opt/tracecat")
    run_command("chown tracecat:tracecat /opt/tracecat")
    run_command("python3 -m venv /opt/tracecat/venv", check=False)
    
    # Install Tracecat package (hypothetical - replace with actual package)
    run_command("/opt/tracecat/venv/bin/pip install tracecat")

    # Configure Tracecat
    run_command("mkdir -p /etc/tracecat")
    es_host = input("\nEnter Elasticsearch host (default: localhost): ") or "localhost"
    es_port = input("Enter Elasticsearch port (default: 9200): ") or "9200"
    
    config = f"""
elasticsearch:
  hosts: ["http://{es_host}:{es_port}"]
  username: elastic
  password: {es_password}
    """
    
    with open("/etc/tracecat/config.yml", "w") as f:
        f.write(config.strip())
    
    run_command("chown -R tracecat:tracecat /etc/tracecat")

def setup_tracecat_service():
    print("\nSetting up Tracecat service...")
    service_content = """
[Unit]
Description=Tracecat SOAR Service
After=network.target elasticsearch.service

[Service]
User=tracecat
Group=tracecat
WorkingDirectory=/opt/tracecat
ExecStart=/opt/tracecat/venv/bin/tracecat start
Restart=always
Environment="PATH=/opt/tracecat/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

[Install]
WantedBy=multi-user.target
    """
    
    with open("/etc/systemd/system/tracecat.service", "w") as f:
        f.write(service_content.strip())
    
    run_command("systemctl daemon-reload")
    run_command("systemctl enable tracecat")
    run_command("systemctl start tracecat")

def main():
    check_environment()
    
    print("This script will install Elasticsearch and Tracecat on Debian 12")
    input("Press Enter to continue or Ctrl-C to cancel...")
    
    install_java()
    install_elasticsearch()
    
    es_password = get_elastic_password()
    if not es_password:
        print("Could not retrieve Elasticsearch password. Check Elasticsearch logs.")
        sys.exit(1)
    
    print(f"\nElasticsearch 'elastic' user password: {es_password}")
    print("Please save this password for future use!")
    
    install_tracecat(es_password)
    setup_tracecat_service()
    
    print("\nInstallation complete!")
    print("Elasticsearch is running on port 9200")
    print("Tracecat service is running and enabled")
    print(f"Elasticsearch credentials: elastic:{es_password}")

if __name__ == "__main__":
    main()
