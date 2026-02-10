import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables from the ai_modules directory explicitly
base_path = os.path.dirname(os.path.abspath(__file__))
dotenv_path = os.path.join(base_path, '.env')
load_dotenv(dotenv_path)

def get_gemini_client():
    """Initializes and returns a Gemini model client."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not found in environment variables.")
    
    genai.configure(api_key=api_key)
    
    # Using gemini-flash-latest as it is the most compatible identifier
    model = genai.GenerativeModel('gemini-flash-latest')
    return model
