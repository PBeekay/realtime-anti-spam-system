# ml_consumer_advanced.py

# --- 1. Import necessary libraries ---
import pika
import json
import time
import re
import redis # Import the Redis library
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
from bs4 import BeautifulSoup, Tag
from pika.exceptions import AMQPConnectionError

# --- 2. Setup Redis Connection & Initial Data ---

# Connect to our local Redis server. The `db=0` is the default database.
# `decode_responses=True` ensures that results from Redis are returned as strings.
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    # Ping the server to check the connection.
    redis_client.ping()
    print("[+] Connected to Redis server successfully!")
except redis.exceptions.ConnectionError as e:
    print(f"[!] FATAL: Could not connect to Redis. Please ensure the 'some-redis' Docker container is running.")
    print(f"Error: {e}")
    exit() # Exit if we can't connect to our core database.

# The key in Redis where we will store our set of blocklisted domains.
BLOCKLIST_KEY = "blocklisted_domains"

# For demonstration, we'll populate the blocklist on startup if it doesn't exist.
# In a real system, this list would be managed by a separate process.
INITIAL_BLOCKLISTED_DOMAINS = {
    "paypal-secure.net", "microsoft-support.info", "secure-login-update.com",
    "apple-security-alert.net", "bankofamerica-verify.org", "billing-paypal-secure.net",
    "vornmarkfinance.com", "rosewatergypsy.com",
}

if not redis_client.exists(BLOCKLIST_KEY):
    print("[*] Populating Redis with initial blocklist...")
    redis_client.sadd(BLOCKLIST_KEY, *INITIAL_BLOCKLISTED_DOMAINS)

# --- 3. Feature Engineering Functions ---

def extract_email_address(header_string):
    if not isinstance(header_string, str): return ""
    match = re.search(r'<([\w\.\-\+]+@[\w\.\-]+)>', header_string)
    if match: return match.group(1)
    if "@" in header_string: return header_string.strip()
    return ""

def get_domain(source_string):
    if not isinstance(source_string, str): return ""
    if "@" in source_string: return source_string.split('@')[-1]
    if source_string.startswith('http'): return urlparse(source_string).netloc
    return source_string

def check_auth_results(headers):
    auth_results = headers.get("authentication_results", {})
    if isinstance(auth_results, dict):
        spf = auth_results.get("spf", "pass")
        dmarc = auth_results.get("dmarc", "pass")
        if "fail" in str(spf) or "fail" in str(dmarc): return 1
    return 0

# --- UPDATED: This function now queries Redis instead of a Python set. ---
def check_domain_reputation(headers, html_body):
    """Checks the sender and link domains against the Redis blocklist."""
    sender_header = headers.get("from", "")
    sender_email = extract_email_address(sender_header)
    sender_domain = get_domain(sender_email)
    
    print(f"Extracted Sender Domain for Reputation Check: '{sender_domain}'")
    # `sismember` is a very fast Redis command to check if an item is in a set.
    if sender_domain and redis_client.sismember(BLOCKLIST_KEY, sender_domain):
        print(f"[!] Reputation Fail: Sender domain '{sender_domain}' is on the blocklist.")
        return 1

    soup = BeautifulSoup(html_body, 'html.parser')
    for a_tag in soup.find_all('a', href=True):
        if isinstance(a_tag, Tag):
            href = str(a_tag.get('href', ''))
            if href.startswith('http'):
                link_domain = get_domain(href)
                print(f"Extracted Link Domain for Reputation Check: '{link_domain}'")
                if link_domain and redis_client.sismember(BLOCKLIST_KEY, link_domain):
                    print(f"[!] Reputation Fail: Link domain '{link_domain}' is on the blocklist.")
                    return 1
    return 0

def check_domain_mismatch(headers, html_body):
    sender_header = headers.get("from", "")
    sender_email = extract_email_address(sender_header)
    sender_domain = get_domain(sender_email)
    if not sender_domain: return 0
    soup = BeautifulSoup(html_body, 'html.parser')
    for a_tag in soup.find_all('a', href=True):
        if isinstance(a_tag, Tag):
            href = str(a_tag.get('href', ''))
            if href.startswith('http'):
                link_domain = get_domain(href)
                if link_domain and link_domain != sender_domain:
                    print(f"[!] Deception Fail: Sender is '{sender_domain}' but link is to '{link_domain}'.")
                    return 1
    return 0

# --- 4. Create and "Train" our AI Model ---
TRAINING_DATASET = [
    ("Subject: Your invoice is overdue Body: please complete your payment immediately to avoid fees", 1),
    ("Subject: Exclusive deal just for you Body: buy now and get 50% off this limited time offer", 1),
    ("Subject: You are a winner! Body: click here to claim your free prize", 1),
    ("Subject: Action required: account suspension Body: verify your details to prevent account suspension", 1),
    ("Subject: Your package is waiting for delivery Body: confirm your shipping address and pay a small fee", 1),
    ("Subject: Cheap pharmaceuticals available Body: get medication without a prescription", 1),
    ("Subject: Work from home opportunity Body: earn thousands weekly with no experience", 1),
    ("Subject: Project Update Body: Here is the latest update on the Q3 project timeline", 0),
    ("Subject: Lunch meeting tomorrow Body: Are you free for lunch tomorrow at 1pm to discuss the report?", 0),
    ("Subject: Your order has shipped Body: Your recent order #58294 has shipped. Tracking included.", 0),
    ("Subject: Quick question Body: Hey, did you get a chance to look at the document I sent over?", 0),
    ("Subject: Family dinner on Saturday Body: Hi everyone, reminder about the family dinner this weekend.", 0),
    ("Subject: IT Department Maintenance Notice Body: Please be advised of scheduled server maintenance tonight.", 0),
    ("Subject: Re: Your presentation slides Body: Thanks for sending those over, they look great!", 0),
]
train_texts = [text for text, label in TRAINING_DATASET]
train_labels = [label for text, label in TRAINING_DATASET]
text_model = make_pipeline(TfidfVectorizer(), RandomForestClassifier())
text_model.fit(train_texts, train_labels)
print("[+] Advanced AI Model trained on EXPANDED dataset!")

# --- 5. Define the callback function ---
def callback(ch, method, properties, body):
    """Processes a full email message using advanced feature engineering."""
    print("\n--- [Advanced AI Worker] Full Email Received ---")
    email_data = json.loads(body.decode())
    
    headers = email_data.get("headers", {})
    html_body = email_data.get("body", {}).get("html", "")
    
    subject = headers.get("subject", "")
    soup = BeautifulSoup(html_body, 'html.parser')
    clean_body = soup.get_text(separator=' ', strip=True)
    full_content = f"Subject: {subject} Body: {clean_body}"
    
    auth_failed_feature = check_auth_results(headers)
    reputation_failed_feature = check_domain_reputation(headers, html_body)
    deception_feature = check_domain_mismatch(headers, html_body)

    print(f"Feature [Auth Failed]: {auth_failed_feature}")
    print(f"Feature [Reputation Failed]: {reputation_failed_feature}")
    print(f"Feature [Deception Detected]: {deception_feature}")

    final_score = 0
    text_spam_probability = text_model.predict_proba([full_content])[0][1]
    final_score += text_spam_probability * 0.2
    print(f"Score from Text Analysis: {final_score:.2f}")

    if auth_failed_feature == 1:
        final_score += 0.15
        print("Score after Auth Check: +0.15")

    if reputation_failed_feature == 1:
        final_score += 0.4
        print("Score after Reputation Check: +0.40")
    
    if deception_feature == 1:
        final_score += 0.5
        print("Score after Deception Check: +0.50")

    print(f"---------------------------------")
    print(f"FINAL SPAM SCORE: {final_score:.2%}")

    if final_score > 0.60:
        print(f"[!] AI Spam DETECTED!")
    else:
        print("[✓] AI thinks message is OK.")

    ch.basic_ack(delivery_tag=method.delivery_tag)
    print("---------------------------------")


# --- 6. Main connection and consumption logic ---
def start_consuming():
    """Sets up the connection and starts listening for messages."""
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        channel = connection.channel()
        channel.queue_declare(queue='message_queue', durable=True)
        print('[*] Advanced AI Worker waiting for messages. To exit press CTRL+C')
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(queue='message_queue', on_message_callback=callback)
        channel.start_consuming()
    except AMQPConnectionError as e:
        print(f"Error connecting to RabbitMQ: {e}. Retrying in 5 seconds...")
        time.sleep(5)
        start_consuming()
    except KeyboardInterrupt:
        print("Interrupted. Shutting down.")
        if 'connection' in locals() and connection.is_open:
            connection.close()

# --- 7. Run the consumer ---
if __name__ == '__main__':
    start_consuming()
