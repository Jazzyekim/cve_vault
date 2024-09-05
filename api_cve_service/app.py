from fastapi import FastAPI

from api_cve_service.routes.router import api_route

app = FastAPI(title="CVE Vault", debug=True)
app.include_router(api_route)
