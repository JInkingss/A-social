from fastapi import FastAPI, Request


app = FastAPI(title="Test Validator")


@app.post("/webhook")
async def verify_message(request: Request):
    payload = await request.json()
    content = str(payload.get("content", ""))

    # Demo rule:
    # - If text contains "虚构" or "不实", return false
    # - Otherwise return true
    if "虚构" in content or "不实" in content:
        verdict = "false"
        reason = "内容疑似不实"
    else:
        verdict = "true"
        reason = "未发现明显事实性问题"

    print("[VALIDATOR] received:", payload)
    print("[VALIDATOR] verdict:", verdict, "reason:", reason)
    return {"verdict": verdict, "reason": reason}


@app.get("/")
def health():
    return {"status": "validator-ok"}
