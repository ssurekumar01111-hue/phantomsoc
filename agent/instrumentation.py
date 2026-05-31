import os
from dotenv import load_dotenv

load_dotenv()


def init_tracing():
    from phoenix.otel import register
    from opentelemetry import trace

    # Set auth headers for Phoenix Cloud
    api_key = os.getenv("PHOENIX_API_KEY", "")
    os.environ["PHOENIX_CLIENT_HEADERS"] = f"api_key={api_key}"

    endpoint = os.getenv(
        "PHOENIX_COLLECTOR_ENDPOINT",
        "https://app.phoenix.arize.com/v1/traces"
    )
    project = os.getenv("PHOENIX_PROJECT_NAME", "phantomsoc")

    print(f"[Phoenix] Connecting to : {endpoint}")
    print(f"[Phoenix] Project name  : {project}")
    print(f"[Phoenix] API key prefix: {api_key[:12]}...")

    # Register Phoenix with auto instrumentation
    tracer_provider = register(
        project_name=project,
        endpoint=endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
        auto_instrument=True,
    )

    # Explicitly instrument google.generativeai (direct Gemini calls)
    try:
        from openinference.instrumentation.google_genai import (
            GoogleGenAIInstrumentor,
        )
        GoogleGenAIInstrumentor().instrument(
            tracer_provider=tracer_provider
        )
        print("[Phoenix] GoogleGenAI instrumentor active")
    except ImportError:
        print("[Phoenix] WARNING: google-genai instrumentor not found")

    # Explicitly instrument Google ADK if used
    try:
        from openinference.instrumentation.google_adk import (
            GoogleADKInstrumentor,
        )
        GoogleADKInstrumentor().instrument(
            tracer_provider=tracer_provider
        )
        print("[Phoenix] GoogleADK instrumentor active")
    except ImportError:
        print("[Phoenix] WARNING: google-adk instrumentor not found")

    print("[Phoenix] Tracing initialized successfully")
    return tracer_provider
