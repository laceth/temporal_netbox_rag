from fastapi import FastAPI
app=FastAPI()


# --- Intent router mount (added) ---
try:
    from .routers.intent import router as intent_router
    app.include_router(intent_router)
except Exception as e:
    print("Intent router not mounted:", e)
