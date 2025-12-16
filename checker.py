import os
import sys
import json
import base64
import requests
import subprocess
import time
import random
import shutil
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
XRAY_BIN = "./xray"  # Assumes xray is in current dir
CHECK_URL = "http://www.google.com" # Or a lighter weight target
TIMEOUT = 10 # Seconds for curl/connect
MAX_THREADS = 50 # Adjust based on runner capability
BATCH_SIZE = 5000 # Save files in chunks of 5000
BASE_PORT = 20000

def parse_vmess(link):
    """Parse vmess:// link to Xray outbound config object."""
    try:
        data = link[8:] # strip vmess://
        # Try decoding base64
        try:
            decoded = base64.b64decode(data).decode('utf-8')
            json_config = json.loads(decoded)
            
            # Extract fields from standard vmess json
            add = json_config.get("add")
            port = int(json_config.get("port", 0))
            uuid = json_config.get("id")
            aid = int(json_config.get("aid", 0))
            net = json_config.get("net", "tcp")
            path = json_config.get("path", "")
            host = json_config.get("host", "")
            if not (add and port and uuid): return None
            
            stream_settings = {
                "network": net,
            }
            if net == "ws":
                stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                
            return {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": add,
                        "port": port,
                        "users": [{"id": uuid, "alterId": aid}]
                    }]
                },
                "streamSettings": stream_settings
            }

        except Exception:
            # Maybe it's not JSON base64, usually vmess is. 
            # If the user script handles URL parameters for vmess, we might need that too.
            # But standard vmess sharing is usually base64 json.
            return None
    except Exception as e:
        return None

def parse_vless(link):
    """Parse vless://uuid@host:port?params#name"""
    try:
        # vless://uuid@host:port?query
        parse = urllib.parse.urlparse(link)
        if parse.scheme != "vless": return None
        
        uuid = parse.username
        host = parse.hostname
        port = parse.port
        params = urllib.parse.parse_qs(parse.query)
        
        if not (uuid and host and port): return None

        net = params.get("type", ["tcp"])[0]
        path = params.get("path", [""])[0]
        encryption = params.get("encryption", ["none"])[0]
        
        stream_settings = {"network": net}
        if net == "ws":
             stream_settings["wsSettings"] = {"path": path}
        
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{"id": uuid, "encryption": encryption}]
                }]
            },
            "streamSettings": stream_settings
        }
    except Exception:
        return None

def parse_trojan(link):
    """Parse trojan://password@host:port?params#name"""
    try:
        parse = urllib.parse.urlparse(link)
        if parse.scheme != "trojan": return None
        
        password = parse.username
        host = parse.hostname
        port = parse.port
        
        if not (password and host and port): return None
        
        return {
            "protocol": "trojan",
            "settings": {
                "servers": [{"address": host, "port": port, "password": password}]
            }
        }
    except Exception:
        return None

def parse_ss(link):
    """Parse ss://base64(method:password)@host:port"""
    try:
        # ss://BASE64@HOST:PORT
        # or ss://method:pass@host:port
        data = link[5:]
        if '@' not in data: return None
        
        user_info, host_info = data.rsplit('@', 1)
        
        # Try generic decode
        try:
             # Fix padding
            padding = len(user_info) % 4
            if padding: user_info += '=' * (4 - padding)
            decoded_user = base64.urlsafe_b64decode(user_info).decode('utf-8')
            if ':' in decoded_user:
                method, password = decoded_user.split(':', 1)
            else:
                return None
        except:
             # Maybe it's plain text ss://method:pass@...
             if ':' in user_info:
                 method, password = user_info.split(':', 1)
             else:
                 return None

        host, port_str = host_info.split(':', 1)
        # remove tag if present
        if '#' in port_str: port_str = port_str.split('#')[0]
        port = int(port_str)

        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{"address": host, "port": port, "method": method, "password": password}]
            }
        }
    except Exception:
        return None

def generate_config(outbound, local_port):
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound]
    }

def check_proxy(link, thread_id):
    """Checks a single proxy link."""
    local_port = BASE_PORT + thread_id
    config_file = f"config_{local_port}.json"
    
    # 1. Parse
    outbound = None
    if link.startswith("vmess://"): outbound = parse_vmess(link)
    elif link.startswith("vless://"): outbound = parse_vless(link)
    elif link.startswith("trojan://"): outbound = parse_trojan(link)
    elif link.startswith("ss://"): outbound = parse_ss(link)
    
    if not outbound:
        return False, link

    # 2. Write Config
    config = generate_config(outbound, local_port)
    with open(config_file, 'w') as f:
        json.dump(config, f)
        
    # 3. Start Xray
    # We use a subprocess. Popen allows us to kill it later.
    try:
        proc = subprocess.Popen([XRAY_BIN, "run", "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Give it a moment to start
        time.sleep(2)
        
        # 4. Curl check
        # curl -x socks5h://127.0.0.1:PORT
        chk_cmd = [
            "curl", "-s", "--connect-timeout", "5", "--max-time", "8",
            "-x", f"socks5h://127.0.0.1:{local_port}",
            CHECK_URL
        ]
        
        try:
            # We look for a 200 OK or just successful exit code with body content
            result = subprocess.run(chk_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0 and len(result.stdout) > 100:
                # Assuming google returns more than 100 bytes
                success = True
            else:
                success = False
        except Exception:
            success = False
            
    except Exception as e:
        success = False
    finally:
        # Cleanup
        if 'proc' in locals():
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        
        if os.path.exists(config_file):
            os.remove(config_file)
            
    return success, link

def fetch_proxies():
    print("Fetching proxies...")
    print("Fetching proxies...")
    links = set()
    
    # CONFIGURATION
    PRIMARY_USER = "sevcator"
    PRIMARY_REPO = "5ubscrpt10n"
    
    # CHANGE THIS to your username for backup (e.g. "YourUsername")
    BACKUP_USER = "olololok"
    BACKUP_REPO = "5ubscrpt10k" # The user's fork name might be different
    
    for r_id in range(1, 37):
        filename = f"m1n1-5ub-{r_id}.txt"
        
        # Try Primary Source
        url = f"https://raw.githubusercontent.com/{PRIMARY_USER}/{PRIMARY_REPO}/main/mini/{filename}"
        
        success = False
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                success = True
            else:
                # If primary fails, try backup
                raise Exception("Status not 200")
        except Exception:
            # Try Backup Source
            url = f"https://raw.githubusercontent.com/{BACKUP_USER}/{BACKUP_REPO}/main/mini/{filename}"
            print(f"Primary failed for {filename}, trying backup: {url}")
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    success = True
            except Exception as e:
                print(f"Failed to fetch {filename} from both sources: {e}")
        
        if success:
            content = resp.text

            # Try base64 decode if it looks like a blob
            if "vmess://" not in content and "vless://" not in content:
                try:
                    decoded = base64.b64decode(content).decode('utf-8')
                    content = decoded
                except:
                    pass
            
            # Extract lines
            for line in content.splitlines():
                line = line.strip()
                if line and (line.startswith("vmess://") or line.startswith("vless://") or 
                             line.startswith("trojan://") or line.startswith("ss://")):
                    links.add(line)
        print(f"Fetched {url} - Total unique: {len(links)}")
    return list(links)

def main():
    if not shutil.which(XRAY_BIN) and not os.path.exists(XRAY_BIN):
        print(f"Error: {XRAY_BIN} not found. Please install Xray-core.")
        sys.exit(1)

    all_links = fetch_proxies()
    print(f"Total proxies to check: {len(all_links)}")
    
    working_proxies = []
    
    # Process Pool might be safer for heavy IO/Subprocess load, but ThreadPool is okay since subproc is external
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_link = {
            executor.submit(check_proxy, link, i % MAX_THREADS): link 
            for i, link in enumerate(all_links)
        }
        
        completed = 0
        for future in as_completed(future_to_link):
            success, link = future.result()
            completed += 1
            if success:
                print(f"[{completed}/{len(all_links)}] WORK: {link[:30]}...")
                working_proxies.append(link)
            else:
                # quiet fail
                pass
                
            if completed % 100 == 0:
                print(f"Progress: {completed}/{len(all_links)} checked. {len(working_proxies)} working.")

    print(f"Finished. Total working: {len(working_proxies)}")
    
    # Save to files
    # Remove old files first
    for f in os.listdir("."):
        if f.startswith("proxy_list_") and f.endswith(".txt"):
            os.remove(f)

    # Split into chunks
    chunk_count = 1
    for i in range(0, len(working_proxies), BATCH_SIZE):
        batch = working_proxies[i : i + BATCH_SIZE]
        filename = f"proxy_list_{chunk_count}.txt"
        with open(filename, "w") as f:
            f.write("\n".join(batch))
        print(f"Saved {len(batch)} proxies to {filename}")
        chunk_count += 1

if __name__ == "__main__":
    main()
