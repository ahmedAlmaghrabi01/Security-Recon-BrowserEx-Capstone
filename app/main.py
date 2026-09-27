from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.routers import dns, whois, subdomains, tech, cve, bugBounty, defender, excutiveSummary, cve2_router, full_report, ssl_tls

app = FastAPI(title="Passive Recon API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins; restrict this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handling middleware
@app.middleware("http")
async def add_exception_handling(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": "An unexpected error occurred.", "error": str(e)},
        )

# Include routers
app.include_router(full_report.router, prefix="/api/full", tags=["Full Reports"])
app.include_router(ssl_tls.router, prefix="/api/ssl_tls", tags=["SSL/TLS"])
app.include_router(dns.router, prefix="/api/dns", tags=["DNS"])
app.include_router(whois.router, prefix="/api/whois", tags=["WHOIS"])
app.include_router(subdomains.router, prefix="/api/subdomains", tags=["Subdomains"])
app.include_router(tech.router, prefix="/api/tech", tags=["Technology"])
app.include_router(cve.router, prefix="/api/cve", tags=["CVE Analysis"])
app.include_router(bugBounty.router, prefix="/api/bounty", tags=["Bug Bounty"])
app.include_router(defender.router, prefix="/api/defense", tags=["Defense Roadmap"])
app.include_router(excutiveSummary.router, prefix="/api/excutives", tags=["Excutives Summary"])
app.include_router(cve2_router.router, prefix="/api/cve2", tags=["CVE2"])





@app.get("/")
def root():
    return {"message": "Welcome to the Passive Recon API"}
