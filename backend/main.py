from fastapi import FastAPI

app = FastAPI(title="Security Hardening Agentless API")

@app.get("/")
def root():
    return {"msg": "Security Hardening API Ready"}

@app.get("/healthz")
def healthz():
    return {"status": "ok"}
