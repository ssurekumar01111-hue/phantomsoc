import os
from dotenv import load_dotenv

load_dotenv()


def init_tracing():
    api_key = os.getenv("PHOENIX_API_KEY", "")
    endpoint = os.getenv(
        "PHOENIX_COLLECTOR_ENDPOINT",
        "https://app.phoenix.arize.com/v1/traces"
    )
    project = os.getenv("PHOENIX_PROJECT_NAME", "phantomsoc")

    print(f"[Phoenix] Connecting to : {endpoint}")
    print(f"[Phoenix] Project name  : {project}")
    print(f"[Phoenix] API key prefix: {api_key[:12]}...")

    # Set environment variables BEFORE any imports
    os.environ["PHOENIX_CLIENT_HEADERS"] = f"api_key={api_key}"
    os.environ["PHOENIX_COLLECTOR_ENDPOINT"] = endpoint

    from phoenix.otel import register

    tracer_provider = register(
        project_name=project,
        endpoint=endpoint,
        headers={"api_key": api_key},
        auto_instrument=True,
    )

    # Instrument google-genai BEFORE genai.configure() is called
    try:
        from openinference.instrumentation.google_genai import (
            GoogleGenAIInstrumentor,
        )
        GoogleGenAIInstrumentor().instrument(
            tracer_provider=tracer_provider
        )
        print("[Phoenix] GoogleGenAI instrumentor active")
    except Exception as e:
        print(f"[Phoenix] WARNING: google-genai instrumentor failed: {e}")

    # Instrument Google ADK
    try:
        from openinference.instrumentation.google_adk import (
            GoogleADKInstrumentor,
        )
        GoogleADKInstrumentor().instrument(
            tracer_provider=tracer_provider
        )
        print("[Phoenix] GoogleADK instrumentor active")
    except Exception as e:
        print(f"[Phoenix] WARNING: google-adk instrumentor failed: {e}")

    print("[Phoenix] Tracing initialized successfully")
    return tracer_provider
