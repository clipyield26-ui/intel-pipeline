"""Async forensic intelligence module. All operations in-memory (bytes streams)."""
import asyncio, hashlib, re, io
from PIL import Image, ExifTags
from concurrent.futures import ThreadPoolExecutor

_executor = ThreadPoolExecutor(max_workers=8)

def phash_bytes(image_bytes: bytes) -> str:
    """dHash -> 64-bit hex fingerprint, robust to resize/recompress."""
    with Image.open(io.BytesIO(image_bytes)) as im:
        im = im.convert("L").resize((9, 8), Image.LANCZOS)
        px = list(im.getdata())
        val = 0
        for y in range(8):
            for x in range(8):
                val = (val << 1) | (1 if px[y*9+x] > px[y*9+x+1] else 0)
        return format(val, "016x")

async def aphash(image_bytes: bytes) -> str:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, phash_bytes, image_bytes)

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _rat_to_float(r):
    try:
        if hasattr(r, "numerator"):
            return float(r.numerator)/float(r.denominator) if r.denominator else 0.0
        if isinstance(r, (tuple, list)) and len(r) == 2:
            return float(r[0])/float(r[1]) if r[1] else 0.0
        return float(r)
    except Exception:
        return 0.0

def gps_to_decimal(dms, ref):
    try:
        d = _rat_to_float(dms[0]); m = _rat_to_float(dms[1]); s = _rat_to_float(dms[2])
        dec = d + m/60.0 + s/3600.0
        if ref in ("S", "W"):
            dec = -dec
        return round(dec, 6)
    except Exception:
        return None

def parse_exif(image_bytes: bytes) -> dict:
    out = {"make": None, "model": None, "software": None, "serial": None, "gps": None, "datetime": None}
    try:
        with Image.open(io.BytesIO(image_bytes)) as im:
            exif = im.getexif()
            if not exif:
                return out
            tags = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
            out["make"] = str(tags.get("Make", "")).strip() or None
            out["model"] = str(tags.get("Model", "")).strip() or None
            out["software"] = str(tags.get("Software", "")).strip() or None
            out["serial"] = str(tags.get("BodySerialNumber") or tags.get("SerialNumber") or "").strip() or None
            out["datetime"] = str(tags.get("DateTimeOriginal") or tags.get("DateTime") or "").strip() or None
            gps = tags.get("GPSInfo")
            if gps:
                lat_ref, lat = gps.get(1), gps.get(2)
                lon_ref, lon = gps.get(3), gps.get(4)
                if lat and lon:
                    la = gps_to_decimal(lat, lat_ref); lo = gps_to_decimal(lon, lon_ref)
                    if la is not None and lo is not None:
                        out["gps"] = {"latitude": la, "longitude": lo,
                                      "maps_url": f"https://www.google.com/maps/search/?api=1&query={la},{lo}"}
    except Exception:
        pass
    return out

async def aparse_exif(image_bytes: bytes) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, parse_exif, image_bytes)

ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.I)
BTC_RE = re.compile(r"\b(bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
ENC_ID_RE = re.compile(r"\b(enc|pgp|key)[-_:]?[A-Fa-f0-9]{8,64}\b")

def scan_text(payload: str) -> dict:
    p = payload or ""
    return {
        "onion_urls": sorted(set(ONION_RE.findall(p))),
        "btc_wallets": sorted(set(BTC_RE.findall(p))),
        "eth_wallets": sorted(set(ETH_RE.findall(p))),
        "xmr_wallets": sorted(set(XMR_RE.findall(p))),
        "encrypted_ids": sorted(set(ENC_ID_RE.findall(p))),
    }

async def ascan_text(payload: str) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, scan_text, payload)

# ---------------- API ----------------
import os, time, hmac, asyncio
from fastapi import FastAPI, UploadFile, File, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

API_TOKEN = os.getenv("API_TOKEN", "change-me-in-production")
FRONTEND_PATH = None

app = FastAPI(title="Intelligence Pipeline", version="1.0.0")
bearer = HTTPBearer(auto_error=False)

_hits: dict[str, list[float]] = {}
WINDOW, LIMIT = 60, 60

def rate_limit(key: str):
    now = time.time()
    arr = [t for t in _hits.get(key, []) if now - t < WINDOW]
    if len(arr) >= LIMIT:
        raise HTTPException(429, "Rate limit exceeded")
    arr.append(now)
    _hits[key] = arr

def verify_token(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if not creds or creds.scheme.lower()!= "bearer":
        raise HTTPException(401, "Missing bearer token")
    if not hmac.compare_digest(creds.credentials, API_TOKEN):
        raise HTTPException(401, "Invalid token")

@app.middleware("http")
async def rl_middleware(request: Request, call_next):
    if request.url.path.startswith("/v1/"):
        ident = request.client.host if request.client else "anon"
        try:
            rate_limit(ident)
        except HTTPException as e:
            return JSONResponse({"detail": e.detail}, status_code=429)
    return await call_next(request)

class TextPayload(BaseModel):
    text: str

@app.post("/v1/ingest-media", dependencies=[Depends(verify_token)])
async def ingest_media(file: UploadFile = File(...)):
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file")
    phash, exif = await asyncio.gather(aphash(data), aparse_exif(data))
    return {"filename": file.filename, "sha256": sha256_hex(data),
            "phash": phash, "exif": exif, "size_bytes": len(data)}

@app.post("/v1/ingest-text", dependencies=[Depends(verify_token)])
async def ingest_text(p: TextPayload, _=Depends(verify_token)):
    findings = await ascan_text(p.text)
    return {"chars": len(p.text), "findings": findings}

@app.get("/health")
async def health():
    return {"ok": True}

@app.get("/", include_in_schema=False)
async def root():
    from fastapi.responses import HTMLResponse
    return HTMLResponse(INDEX_HTML)

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>INTEL // Control Interface</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>body{background:#05080f}.card{background:#0b1220;border:1px solid #1e293b}.glow{box-shadow:0 0 24px rgba(34,211,238,.15)}</style>
</head><body class="text-slate-200 min-h-screen">
<header class="border-b border-slate-800 p-4 flex justify-between items-center">
<div><h1 class="text-xl font-bold tracking-widest text-cyan-300">INTEL PIPELINE</h1><p class="text-xs text-slate-500">Operator Control Interface v1.0</p></div>
<input id="token" type="password" placeholder="Bearer token" class="bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm w-56"/>
</header>
<main class="max-w-6xl mx-auto p-4 grid md:grid-cols-2 gap-4">
<section class="card glow rounded-xl p-5">
<h2 class="font-semibold text-cyan-200 mb-2">File Ingestion</h2>
<div id="drop" class="border-2 border-dashed border-slate-700 rounded-lg p-8 text-center text-slate-400 cursor-pointer">Drag &amp; drop media here or click to browse<input id="file" type="file" class="hidden" accept="image/*"/></div>
<button id="analyze" class="mt-3 w-full bg-cyan-600 hover:bg-cyan-500 text-black font-semibold rounded py-2">Analyze Media</button>
</section>
<section class="card glow rounded-xl p-5">
<h2 class="font-semibold text-cyan-200 mb-2">Text Mining</h2>
<textarea id="txt" rows="7" placeholder="Paste scraped logs / forum strings..." class="w-full bg-slate-900 border border-slate-700 rounded p-3 text-sm"></textarea>
<button id="mine" class="mt-3 w-full bg-emerald-600 hover:bg-emerald-500 text-black font-semibold rounded py-2">Run Regex Extraction</button>
</section>
</main>
<section class="max-w-6xl mx-auto p-4"><h2 class="font-semibold text-cyan-200 mb-2">Intelligence Log</h2><div id="log" class="space-y-3"></div></section>
<script>
const $=id=>document.getElementById(id);
const headers=()=>({"Authorization":"Bearer "+$("token").value});
function card(title,rows){const d=document.createElement("div");d.className="card rounded-xl p-4";d.innerHTML='<h3 class="font-bold text-amber-300 mb-2">'+title+'</h3>'+rows.map(r=>'<div class="text-sm py-1 border-b border-slate-800"><span class="text-slate-500">'+r[0]+':</span> <span class="text-slate-200">'+r[1]+'</span></div>').join("");$("log").prepend(d);}
const drop=$("drop"),fi=$("file");drop.onclick=()=>fi.click();
drop.ondragover=e=>{e.preventDefault();drop.classList.add("border-cyan-400")};
drop.ondragleave=()=>drop.classList.remove("border-cyan-400");
drop.ondrop=e=>{e.preventDefault();fi.files=e.dataTransfer.files;drop.innerHTML="Selected: "+fi.files[0].name};
$("analyze").onclick=async()=>{if(!fi.files[0])return alert("Choose a file");const fd=new FormData();fd.append("file",fi.files[0]);
const r=await fetch("/v1/ingest-media",{method:"POST",headers:headers(),body:fd});const j=await r.json();
if(!r.ok)return card("Media Error",[["status",r.status],["detail",j.detail||JSON.stringify(j)]]);
const gps=j.exif&&j.exif.gps?'<a class="text-cyan-400 underline" target="_blank" href="'+j.exif.gps.maps_url+'">'+j.exif.gps.latitude+', '+j.exif.gps.longitude+'</a>':"--";
card("Media Report / "+j.filename,[["SHA-256","<code class='text-xs'>"+j.sha256+"</code>"],["pHash","<code>"+j.phash+"</code>"],["GPS",gps],["Make/Model",(j.exif.make||"--")+" / "+(j.exif.model||"--")],["Software",j.exif.software||"--"]]);};
$("mine").onclick=async()=>{const r=await fetch("/v1/ingest-text",{method:"POST",headers:Object.assign({},headers(),{"Content-Type":"application/json"}),body:JSON.stringify({text:$("txt").value})});const j=await r.json();
if(!r.ok)return card("Text Error",[["detail",j.detail||"error"]]);const f=j.findings;
card("Text Findings",[["Onion URLs",(f.onion_urls.join(", ")||"--")],["BTC",(f.btc_wallets.join(", ")||"--")],["ETH",(f.eth_wallets.join(", ")||"--")],["XMR",(f.xmr_wallets.join(", ")||"--")],["Enc IDs",(f.encrypted_ids.join(", ")||"--")]]);};
</script></body></html>
"""
