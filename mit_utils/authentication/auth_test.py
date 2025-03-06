from fastapi import FastAPI
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from auth0_auth import Auth0_Auth

app = FastAPI()

auth = Auth0_Auth()


@app.get("/protected-endpoint",dependencies=[Depends(auth.bearer_scheme())])
async def protected_endpoint(token: str = Depends(auth.bearer_scheme())):
    try:
        payload = auth.get_payload(token)
        return {"payload": payload}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )