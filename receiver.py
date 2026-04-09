from fastapi import FastAPI, Request


app = FastAPI(title="Webhook Receiver Demo")


@app.post("/webhook")
async def receive_webhook(request: Request):
    payload = await request.json()
    print("[RECEIVER] got message:")
    print(payload)
    return {"status": "ok"}


@app.get("/")
def health():
    return {"status": "receiver-ok"}
