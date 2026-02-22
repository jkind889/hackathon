import os
from dotenv import load_dotenv
import google.genai as genai


MODEL_CANDIDATES = [
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-flash",
]


def _candidate_models_from_api(client) -> list[str]:
    discovered: list[str] = []
    try:
        for model in client.models.list():
            name = getattr(model, "name", "")
            if not name or "gemini" not in name.lower():
                continue
            discovered.append(name)
            if name.startswith("models/"):
                discovered.append(name.split("/", 1)[1])
    except Exception:
        return []

    ordered: list[str] = []
    seen = set()
    for name in discovered:
        if name not in seen:
            ordered.append(name)
            seen.add(name)
    return ordered

# 1. Load the .env file
load_dotenv()

# 2. Get the key from environment
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("❌ Error: GEMINI_API_KEY not found in .env file!")
else:
    print("✅ API Key loaded successfully.")
    
    # 3. Try a tiny request
    try:
        client = genai.Client(api_key=api_key)
        last_error = None

        discovered_models = _candidate_models_from_api(client)
        models_to_try = discovered_models if discovered_models else MODEL_CANDIDATES

        print("Please wait, sending test request...")
        if discovered_models:
            print(f"Found {len(discovered_models)} Gemini models from API listing.")

        for model_name in models_to_try:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents="Say 'System Online' if you can read this.",
                )
                print(f"✅ Working model: {model_name}")
                print(f"🤖 Gemini says: {getattr(response, 'text', '(No text returned)')}")
                print("✨ Your API key is working perfectly!")
                break
            except Exception as model_error:
                last_error = model_error
                print(f"⚠️ {model_name} unavailable, trying next...")
        else:
            raise last_error if last_error else RuntimeError("No model candidates succeeded.")
        
    except Exception as e:
        print(f"❌ API Request Failed: {e}")