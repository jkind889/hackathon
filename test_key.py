import os
from dotenv import load_dotenv
import google.generativeai as genai

# 1. Load the .env file
load_dotenv()

# 2. Get the key from environment
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("❌ Error: GEMINI_API_KEY not found in .env file!")
else:
    print(f"✅ Found API Key: {api_key[:5]}...{api_key[-4:]}")
    
    # 3. Try a tiny request
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-3-flash-preview')
        
        print("Wait, sending test request...")
        response = model.generate_content("Say 'System Online' if you can read this.")
        
        print(f"🤖 Gemini says: {response.text}")
        print("✨ Your API key is working perfectly!")
        
    except Exception as e:
        print(f"❌ API Request Failed: {e}")