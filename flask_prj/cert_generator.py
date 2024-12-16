import os
import subprocess

def generate_ssl_certificate():
    cert_dir = "/home/flask_prj"
    os.makedirs(cert_dir, exist_ok=True)

    command = [
        "openssl", "req", "-x509", "-nodes", "-days", "365",
        "-newkey", "rsa:2048", "-keyout", f"{cert_dir}/key.pem", "-out", f"{cert_dir}/cert.pem",
        "-subj", "/CN=guardiansofservers.com"
    ]
    subprocess.run(command, check=True)

if __name__ == "__main__":
    generate_ssl_certificate()

