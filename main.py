# main.py

# --- 1. Import necessary libraries ---
import pika
import json
from fastapi import FastAPI, HTTPException
from pika.exceptions import AMQPConnectionError
from pydantic import BaseModel
from typing import Dict, Any

# --- 2. Define the NEW data structure for a full email ---
class EmailBody(BaseModel):
    text: str | None = None
    html: str | None = None

class Email(BaseModel):
    headers: Dict[str, Any]
    body: EmailBody
    metadata: Dict[str, Any]

# --- 3. Create the FastAPI application instance ---
app = FastAPI()

# --- 4. RabbitMQ Connection Logic ---
def publish_to_queue(email: Email):
    """Connects to RabbitMQ and publishes a full email object."""
    try:
        params = pika.ConnectionParameters(host='localhost', blocked_connection_timeout=5)
        connection = pika.BlockingConnection(params)
        
        channel = connection.channel()
        channel.queue_declare(queue='message_queue', durable=True)
        
        message_body = email.model_dump_json()

        channel.basic_publish(
            exchange='',
            routing_key='message_queue',
            body=message_body,
            properties=pika.BasicProperties(delivery_mode=2))

        print("--- Full Email Sent to RabbitMQ ---")
        connection.close()
        return True
    # --- AND THIS IS THE OTHER PART OF THE FIX ---
    except AMQPConnectionError as e:
        print(f"FATAL: Could not connect to RabbitMQ at 'localhost'. Please ensure the Docker container is running and accessible.")
        print(f"Pika Error: {e}")
        return False

# --- 5. Define our API Endpoints (Routes) ---

@app.get("/")
def read_root():
    return {"status": "ok", "message": "Anti-Spam Ingestion API is running!"}

@app.post("/v1/analyze")
def analyze_content(email: Email):
    """
    Receives a full email object, validates it, and publishes it to the queue.
    """
    if publish_to_queue(email):
        return {"status": "received_and_queued", "data": "Full email object received."}
    else:
        raise HTTPException(status_code=503, detail="Service Unavailable: Could not connect to message queue.")
