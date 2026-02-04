"""Example FastAPI app with PromptShield middleware."""

from fastapi import FastAPI

from promptshield.sdk.middleware import PromptShieldMiddleware

app = FastAPI()
app.add_middleware(PromptShieldMiddleware, block_threshold=70)


@app.post("/chat")
async def chat(payload: dict) -> dict:
    prompt = payload.get("prompt", "")
    return {"reply": f"Echo: {prompt}"}
