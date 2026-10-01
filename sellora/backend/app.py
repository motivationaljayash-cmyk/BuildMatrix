import os,re,uuid,secrets,hashlib
from datetime import datetime,timedelta,timezone
from pathlib import Path
from fastapi import FastAPI,HTTPException,Depends,Request,UploadFile,File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse,RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field,EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from jose import jwt,JWTError
import bcrypt

MONGODB_URI=os.getenv("MONGODB_URI",""); MONGODB_DB=os.getenv("MONGODB_DB","sellora")
APP_SECRET=os.getenv("APP_SECRET") or secrets.token_urlsafe(32)
APP_BASE_URL=os.getenv("APP_BASE_URL","http://localhost:8000").rstrip("/")
DEV_SEED=os.getenv("DEV_SEED","false").lower()=="true"
app=FastAPI(title="Sellora API",version="1.0.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
client=AsyncIOMotorClient(MONGODB_URI) if MONGODB_URI else None; db=client[MONGODB_DB] if client else None
ROOT=Path(__file__).resolve().parent; STATIC=ROOT/"static"; UPLOADS=ROOT/"uploads"; UPLOADS.mkdir(exist_ok=True)
if STATIC.exists(): app.mount("/assets",StaticFiles(directory=STATIC),name="assets")
app.mount("/uploads",StaticFiles(directory=UPLOADS),name="uploads")
def now(): return datetime.now(timezone.utc)
def oid(): return str(uuid.uuid4())
def clean(d): d=dict(d); d.pop("_id",None); return d
async def require_db():
    if db is None: raise HTTPException(503,"MongoDB is not configured. Set MONGODB_URI and MONGODB_DB.")
def hp(p): return bcrypt.hashpw(p.encode(),bcrypt.gensalt()).decode()
def vp(p,h): return bcrypt.checkpw(p.encode(),h.encode())
def tok(u): return jwt.encode({"sub":u["id"],"role":u["role"],"exp":now()+timedelta(hours=24)},APP_SECRET,algorithm="HS256")
async def current_user(request:Request):
    a=request.headers.get("Authorization","")
    if not a.startswith("Bearer "): raise HTTPException(401,"Authentication required")
    try: p=jwt.decode(a.split(" ",1)[1],APP_SECRET,algorithms=["HS256"])
    except JWTError: raise HTTPException(401,"Invalid or expired token")
    u=await db.users.find_one({"id":p.get("sub")},{"_id":0})
    if not u: raise HTTPException(401,"User not found")
    return u
def role_required(*roles):
    async def dep(user=Depends(current_user)):
        if user["role"] not in roles: raise HTTPException(403,"Insufficient permissions")
        return user
    return dep

class Signup(BaseModel): name:str=Field(min_length=2,max_length=100); email:EmailStr; password:str=Field(min_length=8,max_length=128); role:str
class Login(BaseModel): email:EmailStr; password:str
class Profile(BaseModel): display_name:str=Field(min_length=2,max_length=100); bio:str=""; website:str=""; categories:list[str]=[]
class ProductIn(BaseModel):
    name:str=Field(min_length=2,max_length=160); description:str=Field(min_length=10,max_length=5000); images:list[str]=[]; category:str
    price:float=Field(gt=0); commission_type:str; commission_value:float=Field(gt=0); stock:int=Field(ge=0); destination_url:str=""
class StatusIn(BaseModel): status:str
class ConversionIn(BaseModel): affiliate_code:str; order_value:float=Field(gt=0); order_reference:str="TEST-ORDER"
class PayoutIn(BaseModel): amount:float=Field(gt=0); method:str=Field(min_length=2,max_length=40); details:dict={}

@app.get("/api/health")
async def health():
    if db is None:return {"ok":False,"database":"not_configured"}
    try: await db.command("ping"); return {"ok":True,"database":"connected"}
    except Exception as e:return {"ok":False,"database":"error","detail":str(e)}

@app.post("/api/auth/signup")
async def signup(data:Signup):
    await require_db(); role=data.role.lower()
    if role not in {"seller","creator"}: raise HTTPException(400,"Role must be seller or creator")
    if await db.users.find_one({"email":data.email.lower()}): raise HTTPException(409,"Email already registered")
    uid=oid(); u={"id":uid,"name":data.name.strip(),"email":data.email.lower(),"password_hash":hp(data.password),"role":role,"status":"active","created_at":now()}
    await db.users.insert_one(u)
    if role=="seller": await db.seller_profiles.insert_one({"id":oid(),"user_id":uid,"display_name":data.name,"bio":"","website":"","created_at":now()})
    else:
        await db.creator_profiles.insert_one({"id":oid(),"user_id":uid,"display_name":data.name,"bio":"","website":"","categories":[],"created_at":now()})
        await db.wallets.insert_one({"id":oid(),"user_id":uid,"pending":0,"approved":0,"available":0,"paid":0})
    return {"token":tok(u),"user":{"id":uid,"name":u["name"],"email":u["email"],"role":role}}

@app.post("/api/auth/login")
async def login(data:Login):
    await require_db(); u=await db.users.find_one({"email":data.email.lower()},{"_id":0})
    if not u or not vp(data.password,u["password_hash"]): raise HTTPException(401,"Invalid email or password")
    if u.get("status")!="active": raise HTTPException(403,"Account is suspended")
    return {"token":tok(u),"user":{"id":u["id"],"name":u["name"],"email":u["email"],"role":u["role"]}}

@app.get("/api/me")
async def me(user=Depends(current_user)):
    c=db.seller_profiles if user["role"]=="seller" else db.creator_profiles
    profile=await c.find_one({"user_id":user["id"]},{"_id":0}) if user["role"]!="admin" else None
    return {"user":{k:user[k] for k in ("id","name","email","role","status")},"profile":profile}

@app.put("/api/profile")
async def update_profile(data:Profile,user=Depends(role_required("seller","creator"))):
    c=db.seller_profiles if user["role"]=="seller" else db.creator_profiles
    await c.update_one({"user_id":user["id"]},{"$set":data.model_dump()}); return {"ok":True}

@app.post("/api/products")
async def create_product(data:ProductIn,user=Depends(role_required("seller"))):
    await require_db()
    if data.commission_type not in {"percentage","fixed"}: raise HTTPException(400,"Invalid commission type")
    if data.commission_type=="percentage" and data.commission_value>100: raise HTTPException(400,"Percentage cannot exceed 100")
    p={"id":oid(),"seller_id":user["id"],**data.model_dump(),"status":"draft","clicks":0,"conversions":0,"sales":0,"created_at":now(),"updated_at":now()}
    await db.products.insert_one(p); return clean(p)

@app.get("/api/products")
async def products(search:str="",category:str="",min_commission:float=0,max_price:float=1e18,sort:str="newest"):
    await require_db(); q={"status":"published","price":{"$lte":max_price},"commission_value":{"$gte":min_commission}}
    if category:q["category"]=category
    if search:q["$or"]=[{"name":{"$regex":re.escape(search),"$options":"i"}},{"description":{"$regex":re.escape(search),"$options":"i"}},{"category":{"$regex":re.escape(search),"$options":"i"}}]
    order=[("created_at",-1)] if sort=="newest" else [("commission_value",-1)] if sort=="commission" else [("clicks",-1)]
    rows=await db.products.find(q,{"_id":0}).sort(order).to_list(100)
    for p in rows:
        s=await db.seller_profiles.find_one({"user_id":p["seller_id"]},{"_id":0,"display_name":1}); p["seller"]=s.get("display_name") if s else "Seller"
    return rows

@app.get("/api/products/mine")
async def my_products(user=Depends(role_required("seller"))):
    return await db.products.find({"seller_id":user["id"]},{"_id":0}).sort("created_at",-1).to_list(200)

@app.patch("/api/products/{product_id}/status")
async def product_status(product_id:str,data:StatusIn,user=Depends(role_required("seller","admin"))):
    if data.status not in {"draft","published","unpublished","rejected"}: raise HTTPException(400,"Invalid product status")
    q={"id":product_id} if user["role"]=="admin" else {"id":product_id,"seller_id":user["id"]}
    r=await db.products.update_one(q,{"$set":{"status":data.status,"updated_at":now()}})
    if not r.matched_count: raise HTTPException(404,"Product not found")
    return {"ok":True}

@app.get("/api/products/{product_id}")
async def product(product_id:str):
    await require_db(); p=await db.products.find_one({"id":product_id},{"_id":0})
    if not p or p.get("status")!="published": raise HTTPException(404,"Product not found")
    s=await db.seller_profiles.find_one({"user_id":p["seller_id"]},{"_id":0}); p["seller"]=s.get("display_name") if s else "Seller"; return p

@app.post("/api/affiliate/{product_id}")
async def affiliate(product_id:str,user=Depends(role_required("creator"))):
    p=await db.products.find_one({"id":product_id,"status":"published"},{"_id":0})
    if not p: raise HTTPException(404,"Product not found")
    link=await db.affiliate_links.find_one({"creator_id":user["id"],"product_id":product_id},{"_id":0})
    if not link:
        code=secrets.token_urlsafe(9).replace("-","").replace("_","")
        link={"id":oid(),"code":code,"creator_id":user["id"],"product_id":product_id,"clicks":0,"conversions":0,"created_at":now()}
        await db.affiliate_links.insert_one(link)
    return {"code":link["code"],"url":f"{APP_BASE_URL}/go/{link['code']}"}

@app.get("/go/{code}")
async def track_and_redirect(code:str,request:Request):
    await require_db(); link=await db.affiliate_links.find_one({"code":code},{"_id":0})
    if not link: raise HTTPException(404,"Affiliate link not found")
    ip=request.client.host if request.client else ""
    await db.clicks.insert_one({"id":oid(),"affiliate_code":code,"creator_id":link["creator_id"],"product_id":link["product_id"],"timestamp":now(),"ip_hash":hashlib.sha256(ip.encode()).hexdigest()})
    await db.affiliate_links.update_one({"code":code},{"$inc":{"clicks":1}}); await db.products.update_one({"id":link["product_id"]},{"$inc":{"clicks":1}})
    p=await db.products.find_one({"id":link["product_id"]},{"_id":0,"destination_url":1}); target=(p or {}).get("destination_url") or f"/products/{link['product_id']}"
    return RedirectResponse(target if target.startswith("http") else f"{APP_BASE_URL}{target}")

@app.post("/api/conversions/test")
async def conversion(data:ConversionIn,user=Depends(role_required("creator","admin"))):
    link=await db.affiliate_links.find_one({"code":data.affiliate_code},{"_id":0})
    if not link: raise HTTPException(404,"Affiliate code not found")
    p=await db.products.find_one({"id":link["product_id"]},{"_id":0})
    if not p: raise HTTPException(404,"Product not found")
    commission=data.order_value*(p["commission_value"]/100) if p["commission_type"]=="percentage" else p["commission_value"]
    order={"id":oid(),"reference":data.order_reference,"product_id":p["id"],"seller_id":p["seller_id"],"creator_id":link["creator_id"],"affiliate_code":data.affiliate_code,"value":data.order_value,"status":"PENDING","created_at":now()}
    conv={"id":oid(),"order_id":order["id"],"affiliate_code":data.affiliate_code,"creator_id":link["creator_id"],"product_id":p["id"],"status":"PENDING","created_at":now()}
    com={"id":oid(),"order_id":order["id"],"creator_id":link["creator_id"],"seller_id":p["seller_id"],"amount":round(commission,2),"status":"PENDING","created_at":now()}
    await db.orders.insert_one(order); await db.conversions.insert_one(conv); await db.commissions.insert_one(com)
    await db.affiliate_links.update_one({"code":data.affiliate_code},{"$inc":{"conversions":1}}); await db.products.update_one({"id":p["id"]},{"$inc":{"conversions":1,"sales":1}})
    return {"order":clean(order),"commission":clean(com)}

@app.get("/api/creator/stats")
async def creator_stats(user=Depends(role_required("creator"))):
    clicks=await db.clicks.count_documents({"creator_id":user["id"]}); conv=await db.conversions.count_documents({"creator_id":user["id"]}); sales=await db.orders.count_documents({"creator_id":user["id"]})
    pending=sum(x.get("amount",0) async for x in db.commissions.find({"creator_id":user["id"],"status":"PENDING"},{"amount":1}))
    approved=sum(x.get("amount",0) async for x in db.commissions.find({"creator_id":user["id"],"status":"APPROVED"},{"amount":1}))
    w=await db.wallets.find_one({"user_id":user["id"]},{"_id":0}) or {"available":approved}
    return {"clicks":clicks,"conversions":conv,"sales":sales,"pending":pending,"approved":approved,"available":w.get("available",approved),"payouts":await db.payout_requests.count_documents({"creator_id":user["id"]})}

@app.get("/api/seller/stats")
async def seller_stats(user=Depends(role_required("seller"))):
    products=await db.products.count_documents({"seller_id":user["id"]}); orders=await db.orders.find({"seller_id":user["id"]},{"value":1}).to_list(10000)
    clicks=sum(x.get("clicks",0) async for x in db.products.find({"seller_id":user["id"]},{"clicks":1})); conversions=sum(x.get("conversions",0) async for x in db.products.find({"seller_id":user["id"]},{"conversions":1}))
    revenue=sum(o.get("value",0) for o in orders); commissions=sum(x.get("amount",0) async for x in db.commissions.find({"seller_id":user["id"],"status":{"$in":["APPROVED","PAID"]}},{"amount":1}))
    return {"products":products,"orders":len(orders),"revenue":revenue,"affiliate_sales":len(orders),"commission_paid":commissions,"clicks":clicks,"conversions":conversions,"conversion_rate":round(conversions/clicks*100,2) if clicks else 0}

@app.get("/api/creator/commissions")
async def creator_commissions(user=Depends(role_required("creator"))): return await db.commissions.find({"creator_id":user["id"]},{"_id":0}).sort("created_at",-1).to_list(200)
@app.get("/api/creator/links")
async def creator_links(user=Depends(role_required("creator"))): return await db.affiliate_links.find({"creator_id":user["id"]},{"_id":0}).sort("created_at",-1).to_list(200)

@app.post("/api/payouts")
async def payout(data:PayoutIn,user=Depends(role_required("creator"))):
    w=await db.wallets.find_one({"user_id":user["id"]},{"_id":0})
    if not w or w.get("available",0)<data.amount: raise HTTPException(400,"Insufficient available balance")
    p={"id":oid(),"creator_id":user["id"],"amount":data.amount,"method":data.method,"details":data.details,"status":"PENDING","created_at":now()}
    await db.payout_requests.insert_one(p); await db.wallets.update_one({"user_id":user["id"]},{"$inc":{"available":-data.amount}}); return clean(p)

@app.get("/api/payouts")
async def payouts(user=Depends(role_required("creator","admin"))):
    q={} if user["role"]=="admin" else {"creator_id":user["id"]}; return await db.payout_requests.find(q,{"_id":0}).sort("created_at",-1).to_list(200)

@app.get("/api/admin/stats")
async def admin_stats(user=Depends(role_required("admin"))):
    v={"users":await db.users.count_documents({}),"sellers":await db.users.count_documents({"role":"seller"}),"creators":await db.users.count_documents({"role":"creator"}),"products":await db.products.count_documents({}),"orders":await db.orders.count_documents({}),"pending_payouts":await db.payout_requests.count_documents({"status":"PENDING"})}
    v["gmv"]=sum(x.get("value",0) async for x in db.orders.find({},{"value":1})); v["commissions"]=sum(x.get("amount",0) async for x in db.commissions.find({},{"amount":1})); return v

@app.get("/api/admin/users")
async def admin_users(user=Depends(role_required("admin"))): return await db.users.find({},{"_id":0,"password_hash":0}).sort("created_at",-1).to_list(500)
@app.post("/api/admin/users/{uid}/status")
async def admin_user_status(uid:str,data:StatusIn,user=Depends(role_required("admin"))):
    if data.status not in {"active","suspended"}: raise HTTPException(400,"Invalid status")
    await db.users.update_one({"id":uid},{"$set":{"status":data.status}}); await db.admin_actions.insert_one({"id":oid(),"admin_id":user["id"],"action":"user_status","target_id":uid,"status":data.status,"created_at":now()}); return {"ok":True}
@app.get("/api/admin/payouts")
async def admin_payouts(user=Depends(role_required("admin"))): return await db.payout_requests.find({},{"_id":0}).sort("created_at",-1).to_list(500)
@app.patch("/api/admin/payouts/{pid}")
async def admin_payout_status(pid:str,data:StatusIn,user=Depends(role_required("admin"))):
    if data.status not in {"PROCESSING","PAID","REJECTED"}: raise HTTPException(400,"Invalid payout status")
    p=await db.payout_requests.find_one({"id":pid},{"_id":0})
    if not p: raise HTTPException(404,"Payout not found")
    await db.payout_requests.update_one({"id":pid},{"$set":{"status":data.status}})
    if data.status=="PAID": await db.wallets.update_one({"user_id":p["creator_id"]},{"$inc":{"paid":p["amount"]}})
    if data.status=="REJECTED": await db.wallets.update_one({"user_id":p["creator_id"]},{"$inc":{"available":p["amount"]}})
    return {"ok":True}
@app.get("/api/admin/conversions")
async def admin_conversions(user=Depends(role_required("admin"))): return await db.conversions.find({},{"_id":0}).sort("created_at",-1).to_list(500)
@app.patch("/api/admin/conversions/{cid}")
async def admin_conversion(cid:str,data:StatusIn,user=Depends(role_required("admin"))):
    if data.status not in {"APPROVED","CANCELLED","REFUNDED"}: raise HTTPException(400,"Invalid conversion status")
    c=await db.conversions.find_one({"id":cid},{"_id":0})
    if not c: raise HTTPException(404,"Conversion not found")
    old=c.get("status"); await db.conversions.update_one({"id":cid},{"$set":{"status":data.status}}); await db.commissions.update_one({"order_id":c["order_id"]},{"$set":{"status":data.status}})
    if data.status=="APPROVED" and old!="APPROVED":
        com=await db.commissions.find_one({"order_id":c["order_id"]},{"_id":0})
        if com: await db.wallets.update_one({"user_id":c["creator_id"]},{"$inc":{"approved":com["amount"],"available":com["amount"]}},upsert=True)
    return {"ok":True}

@app.post("/api/upload")
async def upload(file:UploadFile=File(...),user=Depends(role_required("seller","admin"))):
    ext=Path(file.filename or "").suffix.lower()
    if ext not in {".jpg",".jpeg",".png",".webp"}: raise HTTPException(400,"Only image files are supported")
    name=f"{uuid.uuid4().hex}{ext}"; path=UPLOADS/name; data=await file.read()
    if len(data)>5*1024*1024: raise HTTPException(413,"Image must be 5MB or smaller")
    path.write_bytes(data); return {"url":f"{APP_BASE_URL}/uploads/{name}"}

@app.post("/api/seed")
async def seed():
    if not DEV_SEED: raise HTTPException(404)
    await require_db()
    if await db.users.find_one({"email":"seller@demo.sellora"}): return {"ok":True,"message":"Already seeded"}
    s={"id":oid(),"name":"Demo Seller","email":"seller@demo.sellora","password_hash":hp("DemoSeller123!"),"role":"seller","status":"active","created_at":now()}
    c={"id":oid(),"name":"Demo Creator","email":"creator@demo.sellora","password_hash":hp("DemoCreator123!"),"role":"creator","status":"active","created_at":now()}
    a={"id":oid(),"name":"Admin","email":"admin@demo.sellora","password_hash":hp("DemoAdmin123!"),"role":"admin","status":"active","created_at":now()}
    await db.users.insert_many([s,c,a]); await db.seller_profiles.insert_one({"id":oid(),"user_id":s["id"],"display_name":"Nova Commerce","bio":"Demo merchant","website":""})
    await db.creator_profiles.insert_one({"id":oid(),"user_id":c["id"],"display_name":"Demo Creator","bio":"Creator","website":"","categories":["Technology"]}); await db.wallets.insert_one({"id":oid(),"user_id":c["id"],"pending":0,"approved":0,"available":0,"paid":0})
    await db.categories.insert_many([{"id":oid(),"name":x} for x in ["Technology","Fashion","Beauty","Home","Fitness","Food"]])
    for name,desc,price,ct,cv,cat,img in [
      ("Creator Studio Headphones","Premium wireless headphones built for creators and remote work.",2999,"percentage",20,"Technology","https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=900&q=80"),
      ("Minimal Everyday Backpack","A lightweight everyday backpack with a creator-friendly setup.",1899,"fixed",250,"Fashion","https://images.unsplash.com/photo-1553062407-98eeb64c6a62?auto=format&fit=crop&w=900&q=80")]:
        await db.products.insert_one({"id":oid(),"seller_id":s["id"],"name":name,"description":desc,"images":[img],"category":cat,"price":price,"commission_type":ct,"commission_value":cv,"stock":50,"destination_url":"","status":"published","clicks":0,"conversions":0,"sales":0,"created_at":now(),"updated_at":now()})
    return {"ok":True,"demo_accounts":{"seller":"seller@demo.sellora / DemoSeller123!","creator":"creator@demo.sellora / DemoCreator123!","admin":"admin@demo.sellora / DemoAdmin123!"}}

@app.get("/{full_path:path}")
async def spa(full_path:str):
    index=STATIC/"index.html"
    if index.exists(): return FileResponse(index)
    return {"message":"Sellora API is running","docs":"/docs"}
