import os, re, sqlite3
from difflib import SequenceMatcher
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "qureo_users.db")
DATA_PATH = os.path.join(APP_DIR, "answers.txt")
SECRET = os.environ.get("SECRET_KEY")
if not SECRET:
    raise RuntimeError("Set SECRET_KEY environment variable before running.")
app = Flask(__name__)
app.secret_key = SECRET
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

def load_blocks():
    if not os.path.exists(DATA_PATH): return []
    text = open(DATA_PATH, encoding="utf-8", errors="replace").read()
    lines = text.replace("\r","").split("\n")
    out, cur, level = [], [], None
    for line in lines:
        m = re.search(r"(?:المستوى|level)\s*[:#\-]?\s*(\d+)", line, re.I)
        if m and cur:
            chunk = "\n".join(cur).strip()
            if len(chunk)>20: out.append({"level":level,"text":chunk})
            cur=[]
        if m: level=int(m.group(1))
        cur.append(line)
    chunk="\n".join(cur).strip()
    if len(chunk)>20: out.append({"level":level,"text":chunk})
    if len(out)<2:
        out=[{"level":None,"text":x.strip()} for x in re.split(r"\n{2,}",text) if len(x.strip())>20]
    return out

def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if "uid" not in session: return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapped

@app.get("/")
def index():
    if "uid" not in session: return redirect(url_for("login"))
    return render_template("index.html", username=session.get("username"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        if len(username)<3 or len(password)<8:
            flash("اسم المستخدم 3 أحرف على الأقل وكلمة المرور 8 أحرف على الأقل.")
            return render_template("auth.html", mode="register")
        try:
            with db() as c:
                c.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
                          (username,generate_password_hash(password)))
            flash("تم إنشاء الحساب. سجّل الدخول.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("اسم المستخدم مستخدم بالفعل.")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        with db() as c:
            user=c.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
        if user and check_password_hash(user["password_hash"],password):
            session.clear(); session["uid"]=user["id"]; session["username"]=user["username"]
            return redirect(url_for("index"))
        flash("اسم المستخدم أو كلمة المرور غير صحيح.")
    return render_template("auth.html", mode="login")

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.post("/search")
@login_required
def search():
    q=request.form.get("question","").strip().lower()
    if not q: return jsonify(results=[], error="اكتب السؤال أولًا.")
    blocks=load_blocks()
    qwords=set(re.findall(r"[a-zA-Z0-9_]+|[\u0600-\u06ff]+",q))
    hits=[]
    for i,b in enumerate(blocks):
        words=set(re.findall(r"[a-zA-Z0-9_]+|[\u0600-\u06ff]+",b["text"].lower()))
        overlap=len(qwords & words)/max(1,len(qwords))
        ratio=SequenceMatcher(None,q[:500],b["text"].lower()[:1500]).ratio()
        score=overlap*.8+ratio*.2
        if score>.025: hits.append((score,b,i))
    hits.sort(key=lambda x:x[0],reverse=True)
    return jsonify(results=[{"level":b["level"],"score":round(s*100),"text":b["text"][:2500]} for s,b,i in hits[:10]])

@app.get("/health")
def health(): return {"ok":True}

init_db()
if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT","5000")))
