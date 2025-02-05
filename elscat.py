#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import glob
from getpass import getpass, getuser

def run_command(cmd, check=True):
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, text=True)
    if check and result.returncode != 0:
        print(f"Command failed: {cmd}")
        sys.exit(1)
    return result

def check_environment():
    # Must be run as root
    if getuser() != 'root':
        print("Please run this script as root or with sudo")
        sys.exit(1)
    # Check for Debian GNU/Linux 12 in /etc/os-release
    with open("/etc/os-release") as f:
        content = f.read()
        if "Debian GNU/Linux 12" not in content:
            print("This script requires Debian GNU/Linux 12")
            sys.exit(1)

def install_java():
    print("\nInstalling Java...")
    run_command("apt-get update -qq")
    run_command("apt-get install -y openjdk-17-jdk-headless")

def install_elasticsearch():
    print("\nInstalling Elasticsearch...")
    # Add Elasticsearch GPG key and repository
    run_command("wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg")
    run_command('echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list')
    run_command("apt-get update -qq")
    run_command("apt-get install -y elasticsearch")
    
    # Append configuration for single-node, network binding and enable security (needed for SIEM)
    es_config = "/etc/elasticsearch/elasticsearch.yml"
    with open(es_config, "a") as f:
        f.write("\n# Added by auto-install script\n")
        f.write("discovery.type: single-node\n")
        f.write("network.host: 0.0.0.0\n")
        f.write("xpack.security.enabled: true\n")
    
    # Set JVM heap size via jvm.options.d
    heap_size = input("\nEnter Elasticsearch JVM heap size (e.g., 1g, default: 1g): ") or "1g"
    jvm_options = f"-Xms{heap_size}\n-Xmx{heap_size}\n"
    os.makedirs("/etc/elasticsearch/jvm.options.d/", exist_ok=True)
    with open("/etc/elasticsearch/jvm.options.d/heap.options", "w") as f:
        f.write(jvm_options)
    
    run_command("systemctl daemon-reload")
    run_command("systemctl enable elasticsearch")
    run_command("systemctl start elasticsearch")
    
    print("Waiting 30 seconds for Elasticsearch to initialize...")
    time.sleep(30)
    
    print("\nNOTE: Elasticsearch security is enabled. You must set passwords for the built-in users.")
    print("You can use the command 'elasticsearch-setup-passwords auto' in a separate terminal.")
    elastic_password = getpass("Enter the desired password for the 'elastic' user: ")
    return elastic_password

def install_kibana():
    print("\nInstalling Kibana (Elastic SIEM)...")
    run_command("apt-get update -qq")
    run_command("apt-get install -y kibana")
    
    # Append basic configuration for Kibana
    kibana_config = "/etc/kibana/kibana.yml"
    with open(kibana_config, "a") as f:
        f.write("\n# Added by auto-install script\n")
        f.write("server.host: \"0.0.0.0\"\n")
        f.write("elasticsearch.hosts: [\"http://localhost:9200\"]\n")
        elastic_user = "elastic"
        kibana_password = getpass("Enter the password for Kibana to use with Elasticsearch (should be same as 'elastic'): ")
        f.write(f"elasticsearch.username: \"{elastic_user}\"\n")
        f.write(f"elasticsearch.password: \"{kibana_password}\"\n")
    
    run_command("systemctl daemon-reload")
    run_command("systemctl enable kibana")
    run_command("systemctl start kibana")
    print("Kibana installed and started. (Access via http://your-server-ip:5601)")

def install_tracecat_from_github(elastic_password):
    print("\nInstalling Tracecat from GitHub...")
    # Create system user for Tracecat
    run_command("useradd -r -s /usr/sbin/nologin tracecat")
    
    # Install Python tools
    run_command("apt-get install -y git python3-pip python3-venv")
    
    # Clone the Tracecat repository from GitHub
    tracecat_dir = "/opt/tracecat"
    if not os.path.isdir(tracecat_dir):
        run_command(f"git clone https://github.com/TracecatHQ/tracecat.git {tracecat_dir}")
    else:
        print("Tracecat repository already exists; pulling latest changes...")
        run_command(f"cd {tracecat_dir} && git pull")
    
    run_command(f"chown -R tracecat:tracecat {tracecat_dir}")
    
    # Create and activate a virtual environment in the repository
    venv_dir = f"{tracecat_dir}/venv"
    run_command(f"python3 -m venv {venv_dir}", check=False)
    
    # Install Tracecat in editable mode from the cloned repository
    run_command(f"{venv_dir}/bin/pip install --upgrade pip")
    run_command(f"{venv_dir}/bin/pip install -e {tracecat_dir}")
    
    # Configure Tracecat to use Elasticsearch
    es_host = input("\nEnter Elasticsearch host (default: localhost): ") or "localhost"
    es_port = input("Enter Elasticsearch port (default: 9200): ") or "9200"
    config = f"""
elasticsearch:
  hosts: ["http://{es_host}:{es_port}"]
  username: elastic
  password: {elastic_password}
    """
    os.makedirs("/etc/tracecat", exist_ok=True)
    with open("/etc/tracecat/config.yml", "w") as f:
        f.write(config.strip() + "\n")
    
    run_command("chown -R tracecat:tracecat /etc/tracecat")
    print("Tracecat configured with Elasticsearch settings.")

def setup_tracecat_service():
    print("\nSetting up Tracecat systemd service...")
    service_content = """
[Unit]
Description=Tracecat SOAR Service
After=network.target elasticsearch.service kibana.service

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
        f.write(service_content.strip() + "\n")
    run_command("systemctl daemon-reload")
    run_command("systemctl enable tracecat")
    run_command("systemctl start tracecat")
    print("Tracecat service enabled and started.")

def main():
    check_environment()
    print("This script will auto-install Elasticsearch (with SIEM via Kibana) and Tracecat (from GitHub) on Debian 12.")
    input("Press Enter to continue or Ctrl-C to cancel...")
    
    install_java()
    elastic_password = install_elasticsearch()
    install_kibana()
    install_tracecat_from_github(elastic_password)
    setup_tracecat_service()
    
    print("\nInstallation complete!")
    print("Elasticsearch is running on port 9200 with security enabled.")
    print("Kibana (with Elastic SIEM) is running on port 5601.")
    print("Tracecat (installed from GitHub) is running and configured to use Elasticsearch.")
    print("Please verify passwords and configuration via Kibana and adjust as needed.")

if __name__ == "__main__":
    main()
