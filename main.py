"""
Main entry point for the MVP application.
"""

import uvicorn

if __name__ == "__main__":
    uvicorn.run("src.app.api:app", host="0.0.0.0", port=8000, reload=True)
