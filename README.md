<div align="center">

🛡️ Real-Time Anti-Spam System 🛡️
A multi-layered, server-side application to detect and filter spam, phishing, and malicious emails in real-time using a microservices architecture, advanced heuristics, and a Large Language Model (LLM).

</div>

<p align="center">
<img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
<img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"/>
<img src="https://img.shields.io/badge/RabbitMQ-FF6600?style=for-the-badge&logo=rabbitmq&logoColor=white" alt="RabbitMQ"/>
<img src="https://img.shields.io/badge/redis-%23DD0031.svg?&style=for-the-badge&logo=redis&logoColor=white" alt="Redis"/>
<img src="https://img.shields.io/badge/docker-%230db7ed.svg?&style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
<img src="https://img.shields.io/badge/Gemini_API-4285F4?style=for-the-badge&logo=google-gemini&logoColor=white" alt="Gemini API"/>
</p>

✨ Core Features
This system is designed to be a comprehensive defense against malicious emails by combining multiple layers of analysis:

LLM-Powered Content Analysis: Utilizes the Gemini API for deep contextual understanding of email text to identify sophisticated phishing and scams that keyword-based systems miss.

Heuristic Engine: Scores emails based on common spam characteristics like brand impersonation, sense of urgency, suspicious domain structures, and unrealistic financial gains. Includes localized knowledge for specific regions (e.g., Turkish brands).

Live Reputation Database: Leverages Redis for a high-speed, dynamic blocklist of malicious domains and IPs.

Proactive Threat Intelligence: A dedicated background service continuously fetches data from public threat feeds (e.g., Spamhaus, URLhaus) to keep the reputation database up-to-date with emerging threats.

Resilient Architecture: Built on a microservices model using RabbitMQ, ensuring that components are decoupled, scalable, and fault-tolerant.

🏗️ System Architecture
The application follows a message-driven microservices pattern:

                               +-----------------------------+
[Threat Feeds, Blogs, APIs]--->| Threat Intel Ingestion Svc. |
                               +-----------------------------+
                                             | (writes to)
                                             v
                                     +---------------+
                                     | Redis DB      | (Central Reputation)
                                     +---------------+
                                             ^
                                             | (reads from)
                                             |
[Incoming Email]--->[Ingestion API]--->[Queue]--->[Enterprise AI Worker]

🛠️ Components
Ingestion API (main.py): A lightweight FastAPI server that acts as the public-facing entry point. It validates incoming email data and places it onto the RabbitMQ queue for processing.

Enterprise AI Worker (enterprise_ai_worker.py): The core of the system. This worker consumes emails from the queue and performs a multi-layered analysis, combining the LLM verdict, heuristic score, and reputation checks to generate a final spam score.

Threat Intel Worker (threat_intel_worker.py): A proactive background service that runs independently. It fetches data from external threat intelligence feeds and continuously updates the Redis reputation database, ensuring the system is aware of new threats as they emerge.

🚀 Getting Started
Follow these instructions to get the full system running on your local machine.

Prerequisites
Python 3.8+

Docker and Docker Compose

A Gemini API Key from Google AI Studio

Installation & Setup
Clone the repository:

git clone https://github.com/your-username/realtime-anti-spam-system.git
cd realtime-anti-spam-system

Install Python dependencies:

pip install -r requirements.txt

(You will need to create a requirements.txt file. See below.)

Add your Gemini API Key:
Open the enterprise_ai_worker.py file and paste your API key into the apiKey variable:

# enterprise_ai_worker.py
apiKey = "PASTE_YOUR_GEMINI_API_KEY_HERE"

Launch Backend Services:
Run the following command in your terminal to start the RabbitMQ and Redis containers with Docker:

docker-compose up -d

(You will need to create a docker-compose.yml file. See below.)

Creating Necessary Files
1. requirements.txt:
Create this file in your project root and add the following lines:

fastapi
uvicorn[standard]
pika
redis
requests
beautifulsoup4
scikit-learn

2. docker-compose.yml:
Create this file in your project root. It will manage your RabbitMQ and Redis services easily.

version: '3.8'
services:
  rabbitmq:
    image: rabbitmq:3-management
    container_name: some-rabbit
    ports:
      - "5672:5672"  # For application connection
      - "15672:15672" # For web management UI
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq/

  redis:
    image: redis:latest
    container_name: some-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  rabbitmq_data:
  redis_data:

Running the System
Open three separate terminals in your project directory and run each service:

Terminal 1: Start the API Server

uvicorn main:app --reload

Terminal 2: Start the Threat Intelligence Worker

python threat_intel_worker.py

(Wait for it to complete its first cycle and populate the database.)

Terminal 3: Start the Enterprise AI Worker

python enterprise_ai_worker.py

Your full anti-spam system is now running! You can send test emails to the API endpoint (http://127.0.0.1:8000/v1/analyze) and monitor the output in your worker terminals.
