import os
import requests
import google.generativeai as genai
from dotenv import load_dotenv
from flask import Flask, render_template
from bs4 import BeautifulSoup

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-3-flash-preview')

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')






def find_tos_link(homepage_url):
    try:
        response = requests.get(homepage_url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Keywords weighted by how likely they are to be the main T&C page
        keywords = {
            'terms of service': 10,
            'terms and conditions': 10,
            'terms of use': 10,
            'tos': 8,
            'tou': 8,
            'user agreement': 7,
            'legal': 5,
            'privacy': 3,  # Lower weight as it's often a separate document
        }
        
        best_link = homepage_url
        highest_score = 0

        for link in soup.find_all('a', href=True):
            link_text = link.get_text().lower().strip()
            
            # Calculate score for this link
            current_score = 0
            for word, weight in keywords.items():
                if word in link_text:
                    current_score += weight
            
            # Update best link if this one is a better match
            if current_score > highest_score:
                highest_score = current_score
                from urllib.parse import urljoin
                best_link = urljoin(homepage_url, link['href'])
                
        return best_link
    except:
        return homepage_url

def textsummary(homepage_url):
    target_link = find_tos_link(homepage_url)

    try:
        response = requests.get(target_link, timeout =10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Focus on paragraphs and list items to avoid nav-bar noise
        content = [tag.get_text() for tag in soup.find_all(['p', 'li'])]
        full_text = " ".join(content)
        
        prompt = (
            f"As a legal expert, summarize the Terms of Service for {homepage_url}. "
            "Identify three key areas: Privacy, Costs, and Termination rights. "
            "Use bullet points and bold any concerning clauses."
            "Have it be 500 characters max"
        )
        
        # 4. Generate the content
        # Note: 'model' and 'genai' must be configured at the top of your app
        result = model.generate_content(f"{prompt}\n\nTEXT CONTENT: {full_text[:30000]}")
        
        return {
            "source_url": target_link,
            "summary": result.text
        }
        
    except Exception as e:
        return {"error": f"Could not process {homepage_url}: {str(e)}"}
    

def rate_summary(summarized_text):
    try:

        rating_prompt = (
            "Analyze the following summary of a Terms of Service agreement. "
            "Rate the 'User Friendliness' on a scale of 1 to 10 (10 being best). "
            "Also, give it a letter grade (A-F) based on how predatory the terms are. "
            "Return the response in this format: \n"
            "Score: [X]/10\n"
            "Grade: [Letter]\n"
            "Reasoning: [Short sentence]"
        )

        


        
        response= model.generate_content(f"{rating_prompt}\n\nSUMMARY: {summarized_text}")

        return response.text
    
    except Exception as e:
        return f"Rating failed: {str(e)}"



    
if __name__ == "__main__":
    # This part only runs if you execute 'python app.py' directly
    test_url = "https://www.google.com/"
    print(f"--- Testing Summary for {test_url} ---")
    
    output = textsummary(test_url)
    ratingoutput = rate_summary(output)
    
    if "error" in output:
        print(f"❌ {output['error']}")
    else:
        print(f"✅ Source Found: {output['source_url']}")
        print(f"📝 Summary:\n{output['summary']}")
        print(f"-- ASSESSMENT --\n{ratingoutput}")