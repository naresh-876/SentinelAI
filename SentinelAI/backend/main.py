from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from groq import Groq
from dotenv import load_dotenv
import os
import uvicorn
import json
import re
import requests

load_dotenv()

app = FastAPI()

api_key = os.getenv("GROQ_API_KEY")
if not api_key:
    raise ValueError("GROQ_API_KEY not found in .env file")

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"status": "SentinelAI Cloud Backend is live!"}


def get_threat_intel(logs):
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    unique_ips = list(set(ip_pattern.findall(logs)))[:10]

    intel_data = []
    for ip in unique_ips:
        if ip.startswith(("192.168.", "10.", "172.", "127.")):
            intel_data.append({
                "ip": ip,
                "location": "Internal Network",
                "isp": "Local Host",
                "threat_level": "Low (Internal)"
            })
        else:
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
                if response.get("status") == "success":
                    intel_data.append({
                        "ip": ip,
                        "location": f"{response.get('city', 'Unknown')}, {response.get('country', 'Unknown')}",
                        "isp": response.get("isp", "Unknown"),
                        "threat_level": "High (External Threat)"
                    })
            except Exception:
                pass
    return intel_data


@app.post("/analyze")
async def analyze_logs(file: UploadFile = File(...)):
    content = await file.read()
    logs = content.decode("utf-8")

    print("\nFile received! Extracting IoCs...")
    threat_intel = get_threat_intel(logs)

    system_instr = f"""
    You are SentinelAI, an expert SOC Analyst. Analyze the logs for security threats.
    Threat Intel Context: {json.dumps(threat_intel)}

    You MUST respond ONLY in valid JSON format containing exactly 5 keys. Do not use markdown wrappers around the JSON.
    1. "report": A detailed Markdown formatted incident report.
    2. "timeline": Array of objects: {{"step": 1, "title": "...", "time": "...", "description": "..."}}
    3. "mitre_mapping": Array of objects: {{"tactic": "Initial Access", "techniques": ["T1190"], "description": "..."}}
    4. "root_cause": Array of objects: {{"issue": "...", "explanation": "...", "fix": "..."}}
    5. "graph": A JSON object with "nodes" and "edges" arrays for a network graph.
       - "nodes": [{{"id": 1, "label": "Attacker IP", "group": "attacker"}}, {{"id": 2, "label": "Web Server", "group": "target"}}]
       - "edges": [{{"from": 1, "to": 2, "label": "SQL Injection"}}]
    """

    try:
        print("Sending to Groq Cloud...")
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_instr},
                {"role": "user", "content": f"Analyze these logs and return JSON:\n{logs}"}
            ],
            model="llama-3.3-70b-versatile",
            response_format={"type": "json_object"}
        )

        ai_data = json.loads(chat_completion.choices[0].message.content)
        ai_data["threat_intel"] = threat_intel

        print("Analysis complete!")
        return ai_data

    except Exception as e:
        print(f"Error: {str(e)}")
        return {"error": str(e)}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)