from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="NetOps RAG API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

try:
    from .routers.intent import router as intent_router
    app.include_router(intent_router)
except Exception as e:
    print("Intent router not mounted:", e)

try:
    from .routers.intent_llm import router as llm_router
    app.include_router(llm_router)
except Exception as e:
    print("LLM router not mounted:", e)
