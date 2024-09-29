
import requests

def make_query(role, prompt):
    # very basic AI function

    URL = "https://llama-3-8b-instruct.endpoints.kepler.ai.cloud.ovh.net/api/openai_compat/v1/chat/completions"
    OVH_API_KEY = ""
    
    headers = {
        "Authorization": f"Bearer {OVH_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
    "max_tokens": 512,
    "messages": [
        {
            "content": "Act as a honeypot server, with realistic responses. Only respond with the corresponding data, and nothing else. Do not write explanations.",
            "name": "system",
            "role": "system"
        },
        {
            "content": prompt,
            "name": role,
            "role": role
        }
    ],
    "model": "Meta-Llama-3-8B-Instruct",
    "temperature": 0,
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OVH_API_KEY}",
    }
    
    response = requests.post(URL, json=payload, headers=headers)
    
    if response.status_code == 200:
        response_data = response.json()    
        choices = response_data["choices"]

        for choice in choices:
            text = choice["message"]["content"]
            return text
    else:
        print("Error:", response.status_code)
