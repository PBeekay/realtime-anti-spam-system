# enterprise_ai_worker.py

import pika, json, time, re, redis
import requests # Import the standard requests library
from urllib.parse import urlparse
from bs4 import BeautifulSoup, Tag
from pika.exceptions import AMQPConnectionError

# --- 1. LLM Analysis Engine (The "Real AI") ---
# --- FIX: This function is now synchronous and uses the standard 'requests' library. ---
def analyze_with_llm(subject, body):
    """
    Analyzes email content using the Gemini LLM for deep contextual understanding.
    Returns a dictionary with the verdict ('spam' or 'ham') and the reasoning.
    """
    print("[LLM] Analyzing content with Gemini API...")
    
    prompt = f"""
    You are an expert spam and phishing detection analyst.
    Analyze the following email content and determine if it is 'spam' or 'ham' (legitimate).
    Provide a brief, one-sentence reason for your decision.
    Your response must be a JSON object with two keys: "verdict" and "reason".

    Email Subject: "{subject}"
    Email Body: "{body}"

    JSON Response:
    """

    try:
        # --- IMPORTANT ---
        # You must insert your Gemini API key here.
        # Get one from Google AI Studio: https://aistudio.google.com/app/apikey
        apiKey = "" # <<< PASTE YOUR API KEY HERE

        if not apiKey:
            print("[!] FATAL: Gemini API key is missing. The LLM cannot be called.")
            return {"verdict": "ham", "reason": "API key is missing."}

        chatHistory = [{"role": "user", "parts": [{"text": prompt}]}]
        payload = {"contents": chatHistory}
        apiUrl = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={apiKey}"
        
        # This is the corrected, standard way to make an API call in Python.
        response = requests.post(apiUrl, json=payload, timeout=20)
        
        # This will raise an error if the API returns a 4xx or 5xx status code.
        response.raise_for_status()
        
        result = response.json()

        if result.get('candidates'):
            content_part = result['candidates'][0]['content']['parts'][0]['text']
            cleaned_json_str = content_part.strip().replace('```json', '').replace('```', '')
            llm_response = json.loads(cleaned_json_str)
            print(f"[LLM] Verdict: {llm_response.get('verdict')}. Reason: {llm_response.get('reason')}")
            return llm_response
        else:
            print("[LLM] Warning: Received an unexpected response from the API.")
            print(f"[LLM] API Response: {result}")
            return {"verdict": "ham", "reason": "LLM analysis failed (unexpected response)."}

    except requests.exceptions.HTTPError as e:
        # This handles errors like 400 (Bad Request) or 403 (Forbidden) from the API.
        print(f"[!] FATAL: HTTP Error during LLM call: {e}")
        print(f"[!] API Response Status Code: {e.response.status_code}")
        print(f"[!] API Response Body: {e.response.text}")
        return {"verdict": "ham", "reason": f"API HTTP error: {e.response.status_code}"}
    except requests.exceptions.RequestException as e:
        # This handles network errors (e.g., DNS failure, connection refused).
        print(f"[!] FATAL: Network error during LLM API call: {e}")
        return {"verdict": "ham", "reason": f"API network exception: {e}"}
    except Exception as e:
        # This catches other errors, like failing to parse the JSON response.
        print(f"[!] FATAL: Error processing LLM response: {e}")
        return {"verdict": "ham", "reason": f"API processing exception: {e}"}


# --- 2. Heuristic Analysis Engine ---
MAJOR_BRANDS = {"paypal", "microsoft", "apple", "google", "amazon", "netflix", "tesla"}

def run_heuristic_analysis(subject, body, headers, html_body):
    heuristic_score = 0
    reasons = []
    sender_header, sender_email = headers.get("from", ""), extract_email_address(headers.get("from", ""))
    sender_domain = get_domain(sender_email)

    for brand in MAJOR_BRANDS:
        if brand in sender_domain and not sender_domain.endswith(f".{brand}.com"):
            heuristic_score += 0.5; reasons.append(f"Brand Impersonation: '{sender_domain}'")
            break
    if re.search(r"action required|urgent|account will be suspended|limited time", subject.lower() + body.lower()):
        heuristic_score += 0.15; reasons.append("Sense of Urgency")
    if re.search(r"btc|bitcoin|crypto|giveaway|claim your reward", subject.lower() + body.lower()):
        heuristic_score += 0.25; reasons.append("Unrealistic Financial Gain")
    
    soup = BeautifulSoup(html_body, 'html.parser')
    for a_tag in soup.find_all('a', href=True):
        if isinstance(a_tag, Tag):
            href = str(a_tag.get('href', ''))
            if any(href.endswith(tld) for tld in ['.net', '.info', '.xyz', '.biz']):
                heuristic_score += 0.1; reasons.append(f"Suspicious TLD link: {href}")
                break
    print(f"[Heuristics] Score: {heuristic_score:.2f}. Reasons: {reasons}")
    return heuristic_score


# --- 3. Setup, Helpers & Main Callback ---
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_client.ping(); print("[+] Connected to Redis server successfully!")
except redis.exceptions.ConnectionError as e:
    print(f"[!] FATAL: Could not connect to Redis. Error: {e}"); exit()

BLOCKLIST_KEY = "blocklisted_domains"

def extract_email_address(s):
    if not isinstance(s, str): return ""
    m = re.search(r'<([\w\.\-\+]+@[\w\.\-]+)>', s)
    return m.group(1) if m else (s.strip() if "@" in s else "")
def get_domain(s):
    if not isinstance(s, str): return ""
    return s.split('@')[-1] if "@" in s else (urlparse(s).netloc if s.startswith('http') else s)
def check_auth_results(h):
    a = h.get("authentication_results", {})
    if isinstance(a, dict) and ("fail" in str(a.get("spf", "pass")) or "fail" in str(a.get("dmarc", "pass"))): return 1
    return 0

# --- FIX: This function now uses the more efficient 'sismember' command for all checks. ---
def check_domain_reputation(h, b):
    sender_domain = get_domain(extract_email_address(h.get("from", "")))
    if sender_domain and redis_client.sismember(BLOCKLIST_KEY, sender_domain):
        return 1
    
    soup = BeautifulSoup(b, 'html.parser')
    for a in soup.find_all('a', href=True):
        if isinstance(a, Tag) and str(a.get('href','')).startswith('http'):
            link_domain = get_domain(str(a.get('href','')))
            if link_domain and redis_client.sismember(BLOCKLIST_KEY, link_domain):
                return 1
    return 0

def check_domain_mismatch(h, b):
    sender_domain = get_domain(extract_email_address(h.get("from", "")))
    if not sender_domain: return 0
    soup = BeautifulSoup(b, 'html.parser')
    for a in soup.find_all('a', href=True):
        if isinstance(a, Tag) and str(a.get('href','')).startswith('http'):
            if get_domain(str(a.get('href',''))) != sender_domain: return 1
    return 0

# --- FIX: The callback is now fully synchronous ---
def callback(ch, method, properties, body):
    print("\n--- [Enterprise AI Worker] Message Received ---")
    email_data = json.loads(body.decode())
    headers, html_body = email_data.get("headers", {}), email_data.get("body", {}).get("html", "")
    subject = headers.get("subject", "")
    clean_body = BeautifulSoup(html_body, 'html.parser').get_text(separator=' ', strip=True)

    # --- Evidence Gathering ---
    llm_analysis = analyze_with_llm(subject, clean_body) # Direct synchronous call
    auth_failed = check_auth_results(headers)
    reputation_failed = check_domain_reputation(headers, html_body)
    deception_detected = check_domain_mismatch(headers, html_body)
    heuristic_score = run_heuristic_analysis(subject, clean_body, headers, html_body)

    # --- Final Scoring ---
    llm_verdict = 1 if llm_analysis.get("verdict", "ham").lower() == "spam" else 0
    
    final_score = (llm_verdict * 0.5) + \
                  (reputation_failed * 0.2) + \
                  (deception_detected * 0.15) + \
                  (heuristic_score * 0.15)
    
    print("--- Evidence Report ---")
    print(f"LLM Verdict Score: {llm_verdict * 0.5:.2f} (Reason: {llm_analysis.get('reason')})")
    print(f"Reputation Failure Score: {reputation_failed * 0.2:.2f}")
    print(f"Deception Score: {deception_detected * 0.15:.2f}")
    print(f"Heuristic Score: {heuristic_score * 0.15:.2f}")
    print("-----------------------")
    print(f"FINAL COMBINED SCORE: {final_score:.2%}")

    if final_score > 0.60:
        print(f"[!] SPAM DETECTED!")
    else:
        print("[✓] Message seems OK.")

    ch.basic_ack(delivery_tag=method.delivery_tag)

# --- 5. Main Loop ---
def start_consuming():
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        channel = connection.channel()
        channel.queue_declare(queue='message_queue', durable=True)
        print('[*] Enterprise AI Worker waiting for messages. To exit press CTRL+C')
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(queue='message_queue', on_message_callback=callback)
        channel.start_consuming()
    except AMQPConnectionError as e:
        print(f"Error connecting to RabbitMQ: {e}. Retrying in 5 seconds...")
        time.sleep(5)
        start_consuming()
    except KeyboardInterrupt:
        print("Interrupted.")
        if 'connection' in locals() and connection.is_open:
            connection.close()

if __name__ == '__main__':
    start_consuming()
