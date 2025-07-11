# Real-Time Anti-Spam System

This is a server-side application designed to detect and filter spam in real-time. It uses a microservices architecture with Python, RabbitMQ, Redis, and a connection to the Gemini API for advanced AI analysis.

## Components
- **Ingestion API (`main.py`):** A FastAPI server that receives content.
- **Enterprise AI Worker (`enterprise_ai_worker.py`):** The main analysis engine that uses heuristics, a reputation database (Redis), and the Gemini API to score content.
- **Threat Intel Worker (`threat_intel_worker.py`):** A background service that populates the Redis reputation database from public threat feeds.
