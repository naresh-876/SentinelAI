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

client = Groq(api_key=api_key)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "https://naresh-876.github.io"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"status": "SentinelAI Cloud Backend is live!"}


def is_private_ip(ip: str) -> bool:
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return True

    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                second_octet = int(parts[1])
                return 16 <= second_octet <= 31
            except ValueError:
                return False

    return False


def get_threat_intel(logs: str):
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    unique_ips = list(dict.fromkeys(ip_pattern.findall(logs)))[:10]

    intel_data = []
    for ip in unique_ips:
        if is_private_ip(ip):
            intel_data.append({
                "ip": ip,
                "location": "Internal Network",
                "isp": "Local Host",
                "threat_level": "Low (Internal)"
            })
        else:
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                response.raise_for_status()
                data = response.json()

                if data.get("status") == "success":
                    intel_data.append({
                        "ip": ip,
                        "location": f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}",
                        "isp": data.get("isp", "Unknown"),
                        "threat_level": "High (External Threat)"
                    })
                else:
                    intel_data.append({
                        "ip": ip,
                        "location": "Unknown",
                        "isp": "Unknown",
                        "threat_level": "Medium (Unverified External)"
                    })
            except Exception:
                intel_data.append({
                    "ip": ip,
                    "location": "Unknown",
                    "isp": "Unknown",
                    "threat_level": "Medium (Lookup Failed)"
                })

    return intel_data


@app.post("/analyze")
async def analyze_logs(file: UploadFile = File(...)):
    content = await file.read()
    logs = content.decode("utf-8", errors="ignore").strip()

    if not logs:
        return {"error": "Uploaded file is empty or could not be decoded as readable text."}

    print("\nFile received! Extracting IoCs...")
    threat_intel = get_threat_intel(logs)

    system_instr = f"""
You are SentinelAI, an expert SOC Analyst. Analyze the provided logs for security threats.

Threat Intel Context:
{json.dumps(threat_intel)}

Return ONLY valid JSON.
Do not wrap the JSON in markdown.
Do not include any text outside the JSON.

The JSON must contain exactly these 6 keys:

1. "summary"
A concise executive summary in plain text, 1 to 2 paragraphs only.
It must summarize:
- overall incident nature
- severity
- likely attacker behavior
- most important remediation priorities

2. "timeline"
Array of objects in this format:
{{"step": 1, "title": "...", "time": "...", "description": "..."}}

3. "mitre_mapping"
Array of objects in this format:
{{"tactic": "Initial Access", "techniques": ["T1190"], "description": "..."}}

4. "root_cause"
Array of objects in this format:
{{"issue": "...", "explanation": "...", "fix": "..."}}

5. "graph"
A JSON object with:
- "nodes": [{{"id": 1, "label": "Attacker IP", "group": "attacker"}}, {{"id": 2, "label": "Web Server", "group": "target"}}]
- "edges": [{{"from": 1, "to": 2, "label": "SQL Injection"}}]

6. "report"
A structured markdown-style report with these headings:
## Incident Overview
## Severity Assessment
## Key Indicators of Compromise
## Attack Flow Summary
## Timeline Highlights
## MITRE ATT&CK Mapping Summary
## Root Cause Analysis
## Recommended Immediate Actions
## Long-Term Hardening Recommendations

Rules:
- Base findings only on the logs and threat intel context.
- If evidence is limited, say so clearly.
- Keep entries specific and realistic.
- The "summary" should be short and executive-friendly.
- The "report" should be fuller and sectioned.
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