from fastapi import FastAPI

app = FastAPI(title="NTRO Threat Detector")

@app.get("/")
def read_root():
    return {"status": "running"}
