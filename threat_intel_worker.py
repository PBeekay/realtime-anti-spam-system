# threat_intel_worker.py

# --- 1. Import necessary libraries ---
import requests
import redis
import time

# --- 2. Configuration ---

BLOCKLIST_KEY = "blocklisted_domains"

# --- UPGRADE: More powerful and diverse threat feeds ---
# We are now pulling from multiple sources, including lists of known
# phishing domains, malware domains, and general spam domains.
THREAT_FEEDS = {
    # Spamhaus lists of hijacked/spamming netblocks
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "spamhaus_edrop": "https://www.spamhaus.org/drop/edrop.txt",
    # URLhaus list of domains associated with malware distribution
    "urlhaus_malware_domains": "https://urlhaus.abuse.ch/downloads/hostfile/",
}

# How often to check for new intelligence (in seconds).
UPDATE_INTERVAL = 900 # 15 minutes

# --- 3. Setup Redis Connection ---
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_client.ping()
    print("[+] Connected to Redis server successfully!")
except redis.exceptions.ConnectionError as e:
    print(f"[!] FATAL: Could not connect to Redis. Please ensure the 'some-redis' Docker container is running.")
    print(f"Error: {e}")
    exit()

# --- 4. Core Logic ---

def fetch_and_parse_feed(url):
    """Downloads a blocklist feed and parses out domains/IPs."""
    print(f"[*] Fetching threat feed from: {url}")
    try:
        # Some feeds may block default user agents, so we'll use a common one.
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}
        response = requests.get(url, timeout=20, headers=headers)
        response.raise_for_status()
        
        entries = set()
        lines = response.text.splitlines()
        
        for line in lines:
            # Ignore comments and local addresses
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith(';') and not line.startswith('127.0.0.1'):
                # The entry can be an IP or a domain. We take the second part.
                parts = line.split()
                if len(parts) > 1:
                    entry = parts[1].strip()
                    entries.add(entry)
        
        print(f"[*] Found {len(entries)} new potential threats from {url}")
        return entries
        
    except requests.exceptions.RequestException as e:
        print(f"[!] Warning: Could not fetch feed from {url}. Error: {e}")
        return set()

def update_reputation_database():
    """Main function to fetch all feeds and update Redis."""
    print("\n--- Starting Threat Intelligence Update Cycle ---")
    
    all_new_threats = set()
    for feed_name, feed_url in THREAT_FEEDS.items():
        threats_from_feed = fetch_and_parse_feed(feed_url)
        all_new_threats.update(threats_from_feed)
    
    if not all_new_threats:
        print("[*] No new threats found in this cycle.")
        return

    pipeline = redis_client.pipeline()
    pipeline.sadd(BLOCKLIST_KEY, *all_new_threats)
    pipeline.execute()
    
    total_threats = redis_client.scard(BLOCKLIST_KEY)
    
    print(f"[+] Successfully added/updated {len(all_new_threats)} unique entries in the Redis blocklist.")
    print(f"[+] Total threats in database: {total_threats}")
    print("--- Finished Threat Intelligence Update Cycle ---")


# --- 5. Main Loop ---
if __name__ == "__main__":
    while True:
        update_reputation_database()
        print(f"\n[*] Sleeping for {UPDATE_INTERVAL // 60} minutes...")
        time.sleep(UPDATE_INTERVAL)
