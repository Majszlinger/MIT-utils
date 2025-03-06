from fastapi import FastAPI
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from auth0_auth import Auth0_Auth
import uvicorn

app = FastAPI()

auth = Auth0_Auth(domain="mit-solutions.eu.auth0.com",audience="https://data-collector.hellenergy.hu/api")


@app.get("/protected-endpoint",dependencies=[Depends(auth.bearer_scheme)])
async def protected_endpoint(token: str = Depends(auth.get_payload())):
    return token

if __name__ == "__main__":
    import nest_asyncio
    nest_asyncio.apply()
    uvicorn.run(app, host="0.0.0.0", port=8000,reload=True)
    
