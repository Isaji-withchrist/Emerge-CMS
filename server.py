#!/usr/bin/env python3
"""
EMERGE CMS — Production Backend
Flask + SQLite  |  Run: python3 server.py  |  http://localhost:5000
"""
import sqlite3, hashlib, hmac, json, os, time, base64, re, mimetypes, secrets
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, send_file, g

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(BASE_DIR, 'emerge.db')
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
PUBLIC_DIR  = os.path.join(BASE_DIR, 'public')
SECRET_KEY  = os.environ.get('EMERGE_SECRET', 'emerge-dev-' + secrets.token_hex(16))
TOKEN_TTL   = 60 * 60 * 24 * 7
MAX_UPLOAD  = 20 * 1024 * 1024
ALLOWED_EXT = {'jpg','jpeg','png','gif','webp','svg','pdf','doc','docx','xls','xlsx','txt','mp4','mov','webm'}

os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(PUBLIC_DIR,  exist_ok=True)

app = Flask(__name__, static_folder=PUBLIC_DIR, static_url_path='')
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def Q(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rs  = cur.fetchall()
    return (rs[0] if rs else None) if one else rs

def X(sql, args=()):
    db = get_db(); c = db.execute(sql, args); db.commit(); return c

def R(r): return dict(r) if r else None
def Rs(rs): return [dict(r) for r in rs]

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, first_name TEXT NOT NULL, last_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE, password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT "author" CHECK(role IN ("administrator","editor","author","visitor")),
        status TEXT NOT NULL DEFAULT "active" CHECK(status IN ("active","suspended")),
        bio TEXT DEFAULT "", color TEXT DEFAULT "#6B8CFF",
        created_at TEXT NOT NULL, last_login TEXT
    );
    CREATE TABLE IF NOT EXISTS invite_codes (
        id TEXT PRIMARY KEY, code TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL CHECK(role IN ("administrator","editor")),
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        used_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        used_at TEXT, expires_at TEXT, note TEXT DEFAULT "", created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS setup_state (done INTEGER DEFAULT 0, done_at TEXT);
    CREATE TABLE IF NOT EXISTS categories (
        id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, slug TEXT NOT NULL UNIQUE,
        description TEXT DEFAULT "", color TEXT DEFAULT "#6B8CFF", created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS posts (
        id TEXT PRIMARY KEY, title TEXT NOT NULL DEFAULT "Untitled",
        slug TEXT NOT NULL UNIQUE, body TEXT DEFAULT "", excerpt TEXT DEFAULT "",
        status TEXT NOT NULL DEFAULT "draft" CHECK(status IN ("draft","pending","published","archived")),
        author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        category_id TEXT REFERENCES categories(id) ON DELETE SET NULL,
        meta_title TEXT DEFAULT "", meta_desc TEXT DEFAULT "",
        allow_comments INTEGER DEFAULT 1, views INTEGER DEFAULT 0,
        published_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS post_tags (
        post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        tag TEXT NOT NULL, PRIMARY KEY (post_id, tag)
    );
    CREATE TABLE IF NOT EXISTS comments (
        id TEXT PRIMARY KEY,
        post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        visitor_name TEXT NOT NULL, visitor_email TEXT NOT NULL, body TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT "pending" CHECK(status IN ("pending","approved","rejected")),
        moderated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        moderated_at TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS media (
        id TEXT PRIMARY KEY, filename TEXT NOT NULL, original_name TEXT NOT NULL,
        mime_type TEXT NOT NULL, size INTEGER NOT NULL, alt_text TEXT DEFAULT "",
        uploaded_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        icon TEXT DEFAULT "bell", icon_bg TEXT DEFAULT "rgba(107,140,255,.12)",
        text TEXT NOT NULL, link TEXT DEFAULT "dashboard",
        is_read INTEGER DEFAULT 0, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_posts_author   ON posts(author_id);
    CREATE INDEX IF NOT EXISTS idx_posts_status   ON posts(status);
    CREATE INDEX IF NOT EXISTS idx_comments_post  ON comments(post_id);
    CREATE INDEX IF NOT EXISTS idx_notifs_user    ON notifications(user_id);
    CREATE INDEX IF NOT EXISTS idx_invites_code   ON invite_codes(code);
    ''')
    defs = {
        'site_name':'Emerge','tagline':'','posts_per_page':'10','default_status':'draft',
        'require_review':'1','comment_mod':'1','allow_reg':'1',
        'notif_post_submit':'1','notif_post_approved':'1','notif_post_rejected':'1',
        'notif_new_comment':'0','notif_weekly':'1',
        'sec_two_factor':'0','sec_login_alerts':'1','sec_session_timeout':'1',
    }
    for k,v in defs.items():
        db.execute('INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)',(k,v))
    db.commit(); db.close()
    print(f'Database ready: {DB_PATH}')

def hash_pw(pw):
    s = os.urandom(32)
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), s, 390000)
    return base64.b64encode(s+dk).decode()

def check_pw(pw, stored):
    try:
        raw=base64.b64decode(stored); s=raw[:32]; dk=raw[32:]
        return hmac.compare_digest(dk, hashlib.pbkdf2_hmac('sha256',pw.encode(),s,390000))
    except: return False

def b64u(d):
    if isinstance(d,str): d=d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

def b64ud(d):
    return base64.urlsafe_b64decode(d+'=='[:4-len(d)%4])

def make_token(uid, role):
    h = b64u(json.dumps({'alg':'HS256','typ':'JWT'}))
    p = b64u(json.dumps({'sub':uid,'role':role,'iat':int(time.time()),'exp':int(time.time())+TOKEN_TTL}))
    s = b64u(hmac.new(SECRET_KEY.encode(),f'{h}.{p}'.encode(),hashlib.sha256).digest())
    return f'{h}.{p}.{s}'

def verify_token(token):
    try:
        h,p,s = token.split('.')
        exp = b64u(hmac.new(SECRET_KEY.encode(),f'{h}.{p}'.encode(),hashlib.sha256).digest())
        if not hmac.compare_digest(s,exp): return None
        d = json.loads(b64ud(p))
        return None if d.get('exp',0)<time.time() else d
    except: return None

def auth(roles=None):
    def dec(fn):
        @wraps(fn)
        def wrap(*a,**kw):
            tk = request.headers.get('Authorization','')
            tk = tk[7:] if tk.startswith('Bearer ') else None
            if not tk: return jsonify({'error':'Authentication required'}),401
            pl = verify_token(tk)
            if not pl: return jsonify({'error':'Token invalid or expired'}),401
            u = R(Q('SELECT * FROM users WHERE id=?',(pl['sub'],),one=True))
            if not u: return jsonify({'error':'User not found'}),401
            if u['status']=='suspended': return jsonify({'error':'Account suspended'}),403
            if roles and u['role'] not in roles:
                return jsonify({'error':f'Requires role: {", ".join(roles)}'}),403
            g.cu=u; return fn(*a,**kw)
        return wrap
    return dec

def cu(): return g.get('cu')

def now(): return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
def nid(): return secrets.token_hex(10)

def mslug(title, excl=None):
    base = re.sub(r'[^\w\s-]','',title.lower())
    base = re.sub(r'[\s_]+','-',base).strip('-')[:80] or 'post'
    slug,i = base,2
    while True:
        sql,args = 'SELECT id FROM posts WHERE slug=?',[slug]
        if excl: sql+=' AND id!=?'; args.append(excl)
        if not Q(sql,args,one=True): break
        slug=f'{base}-{i}'; i+=1
    return slug

def cfg(k,d=''): r=Q('SELECT value FROM settings WHERE key=?',(k,),one=True); return r['value'] if r else d

def notif(uid, text, icon='bell', ibg='rgba(107,140,255,.12)', link='dashboard'):
    X('INSERT INTO notifications(id,user_id,icon,icon_bg,text,link,created_at) VALUES(?,?,?,?,?,?,?)',
      (nid(),uid,icon,ibg,text,link,now()))

def enrich(p):
    if not p: return p
    pid = p['id']
    p['tags']    = [r['tag'] for r in Q('SELECT tag FROM post_tags WHERE post_id=? ORDER BY tag',(pid,))]
    p['author']  = R(Q('SELECT id,first_name,last_name,role,color FROM users WHERE id=?',(p['author_id'],),one=True))
    p['category']= R(Q('SELECT id,name,color FROM categories WHERE id=?',(p['category_id'],),one=True)) if p.get('category_id') else None
    return p

@app.after_request
def cors(r):
    r.headers['Access-Control-Allow-Origin']  = '*'
    r.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    r.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,PATCH,DELETE,OPTIONS'
    return r

@app.before_request
def preflight():
    if request.method=='OPTIONS':
        from flask import Response; return Response(status=204)

# ── SETUP ──────────────────────────────────────────
@app.route('/api/setup/status')
def setup_status():
    r  = Q('SELECT done FROM setup_state',one=True)
    sn = Q('SELECT value FROM settings WHERE key="site_name"',one=True)
    return jsonify({'done':bool(r and r['done']),'user_count':len(Q('SELECT id FROM users')),'site_name':sn['value'] if sn else 'Emerge'})

@app.route('/api/setup/complete',methods=['POST'])
@auth(['administrator'])
def setup_complete():
    d = request.get_json() or {}
    for k,v in {'site_name':d.get('site_name','Emerge').strip() or 'Emerge','tagline':d.get('tagline','').strip(),
                'require_review':'1' if d.get('require_review',True) else '0',
                'comment_mod':'1' if d.get('comment_mod',True) else '0'}.items():
        X('UPDATE settings SET value=? WHERE key=?',(v,k))
    for c in d.get('categories',[]):
        nm=c.get('name','').strip()
        if nm:
            sl=re.sub(r'[^\w-]','-',nm.lower()).strip('-')
            X('INSERT OR IGNORE INTO categories(id,name,slug,description,color,created_at) VALUES(?,?,?,?,?,?)',
              (nid(),nm,sl,c.get('description',''),c.get('color','#6B8CFF'),now()))
    X('DELETE FROM setup_state')
    X('INSERT INTO setup_state(done,done_at) VALUES(1,?)',(now(),))
    return jsonify({'ok':True})

# ── INVITE CODES ───────────────────────────────────
@app.route('/api/invites',methods=['GET'])
@auth(['administrator'])
def list_invites():
    return jsonify(Rs(Q('''SELECT i.*,
        u1.first_name||" "||u1.last_name as creator_name,
        u2.first_name||" "||u2.last_name as used_by_name
        FROM invite_codes i
        LEFT JOIN users u1 ON i.created_by=u1.id
        LEFT JOIN users u2 ON i.used_by=u2.id
        ORDER BY i.created_at DESC''')))

@app.route('/api/invites',methods=['POST'])
@auth(['administrator'])
def create_invite():
    d = request.get_json() or {}
    role = d.get('role','editor')
    if role not in ('administrator','editor'):
        return jsonify({'error':'Invites only for administrator or editor'}),400
    raw  = secrets.token_hex(6).upper()
    code = f'{raw[:4]}-{raw[4:8]}-{raw[8:12]}'
    X('INSERT INTO invite_codes(id,code,role,created_by,note,created_at) VALUES(?,?,?,?,?,?)',
      (nid(),code,role,cu()['id'],d.get('note','').strip(),now()))
    return jsonify(R(Q('SELECT * FROM invite_codes WHERE code=?',(code,),one=True))),201

@app.route('/api/invites/<iid>',methods=['DELETE'])
@auth(['administrator'])
def delete_invite(iid):
    inv = R(Q('SELECT * FROM invite_codes WHERE id=?',(iid,),one=True))
    if not inv: return jsonify({'error':'Not found'}),404
    if inv['used_by']: return jsonify({'error':'Cannot delete a used code'}),400
    X('DELETE FROM invite_codes WHERE id=?',(iid,))
    return jsonify({'ok':True})

@app.route('/api/invites/validate',methods=['POST'])
def validate_invite():
    code = (request.get_json() or {}).get('code','').strip().upper()
    if not code: return jsonify({'valid':False,'error':'No code provided'}),400
    inv = R(Q('SELECT * FROM invite_codes WHERE code=? AND used_by IS NULL',(code,),one=True))
    if not inv: return jsonify({'valid':False,'error':'Invalid or already-used invite code'}),400
    if inv['expires_at'] and inv['expires_at']<now():
        return jsonify({'valid':False,'error':'Invite code has expired'}),400
    return jsonify({'valid':True,'role':inv['role'],'code':code})

# ── AUTH ───────────────────────────────────────────
@app.route('/api/auth/register',methods=['POST'])
def register():
    d = request.get_json() or {}
    fn = d.get('first_name','').strip()
    ln = d.get('last_name','').strip()
    em = d.get('email','').strip().lower()
    pw = d.get('password','')
    role = d.get('role','author')
    ic = d.get('invite_code','').strip().upper()

    if not all([fn,ln,em,pw]):
        return jsonify({'error':'All fields required'}),400

    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$',em):
        return jsonify({'error':'Invalid email'}),400

    if len(pw) < 8:
        return jsonify({'error':'Password min 8 characters'}),400

    if role not in ('administrator','editor','author','visitor'):
        return jsonify({'error':'Invalid role'}),400

    if Q('SELECT id FROM users WHERE email=?',(em,),one=True):
        return jsonify({'error':'Email already registered'}),409

    # ✅ FIX: First user becomes admin automatically
    user_count = len(Q('SELECT id FROM users'))

    if role in ('administrator','editor'):
        if user_count == 0:
            role = 'administrator'
        else:
            if not ic:
                return jsonify({
                    'error': f'An invite code is required to register as {role}',
                    'needs_invite': True
                }), 403

            inv = R(Q(
                'SELECT * FROM invite_codes WHERE code=? AND used_by IS NULL AND role=?',
                (ic, role),
                one=True
            ))

            if not inv:
                return jsonify({'error': 'Invalid, used, or wrong-role invite code'}), 403

            if inv['expires_at'] and inv['expires_at'] < now():
                return jsonify({'error': 'Invite code expired'}), 403

    if role == 'author' and cfg('allow_reg','1') == '0':
        return jsonify({'error':'Open registration is disabled. Request an invite.'}),403

    colors = ['#6B8CFF','#34D399','#FBB040','#F87171','#A78BFA','#38BDF8','#FB923C','#4ADE80']
    color = colors[len(Q('SELECT id FROM users')) % len(colors)]

    uid = nid()

    X('INSERT INTO users(id,first_name,last_name,email,password,role,color,created_at) VALUES(?,?,?,?,?,?,?,?)',
      (uid,fn,ln,em,hash_pw(pw),role,color,now()))

    if role in ('administrator','editor') and ic:
        X('UPDATE invite_codes SET used_by=?,used_at=? WHERE code=?',(uid,now(),ic))

    for admin in Q("SELECT id FROM users WHERE role='administrator' AND id!=?",(uid,)):
        notif(admin['id'],
              f'<strong>{fn} {ln}</strong> registered as {role}',
              'user-plus','rgba(251,176,64,.12)','users')

    token = make_token(uid,role)

    u = R(Q('SELECT id,first_name,last_name,email,role,status,bio,color,created_at FROM users WHERE id=?',(uid,),one=True))

    return jsonify({'token':token,'user':u}),201
@app.route('/api/auth/login',methods=['POST'])
def login():
    d=request.get_json() or {}
    em=d.get('email','').strip().lower(); pw=d.get('password','')
    if not em or not pw: return jsonify({'error':'Email and password required'}),400
    u=R(Q('SELECT * FROM users WHERE email=?',(em,),one=True))
    if not u or not check_pw(pw,u['password']): return jsonify({'error':'Invalid email or password'}),401
    if u['status']=='suspended': return jsonify({'error':'Account suspended. Contact an administrator.'}),403
    X('UPDATE users SET last_login=? WHERE id=?',(now(),u['id']))
    token=make_token(u['id'],u['role'])
    return jsonify({'token':token,'user':{k:v for k,v in u.items() if k!='password'}})

@app.route('/api/auth/me')
@auth()
def me(): return jsonify({k:v for k,v in cu().items() if k!='password'})

# ── SETTINGS ──────────────────────────────────────
@app.route('/api/settings')
@auth()
def get_settings(): return jsonify({r['key']:r['value'] for r in Q('SELECT key,value FROM settings')})

@app.route('/api/settings',methods=['PUT'])
@auth(['administrator'])
def upd_settings():
    d=request.get_json() or {}
    ok=['site_name','tagline','posts_per_page','default_status','require_review','comment_mod','allow_reg',
        'notif_post_submit','notif_post_approved','notif_post_rejected','notif_new_comment','notif_weekly',
        'sec_two_factor','sec_login_alerts','sec_session_timeout']
    for k,v in d.items():
        if k in ok: X('UPDATE settings SET value=? WHERE key=?',(str(v),k))
    return jsonify({'ok':True})

# ── USERS ──────────────────────────────────────────
@app.route('/api/users')
@auth(['administrator','editor'])
def list_users():
    us=Rs(Q('SELECT id,first_name,last_name,email,role,status,bio,color,created_at,last_login FROM users ORDER BY created_at'))
    pc={r['author_id']:r['cnt'] for r in Q('SELECT author_id,COUNT(*) as cnt FROM posts GROUP BY author_id')}
    for u in us: u['post_count']=pc.get(u['id'],0)
    return jsonify(us)

@app.route('/api/users',methods=['POST'])
@auth(['administrator'])
def create_user():
    d=request.get_json() or {}
    fn=d.get('first_name','').strip(); ln=d.get('last_name','').strip()
    em=d.get('email','').strip().lower(); pw=d.get('password','')
    rl=d.get('role','author'); bio=d.get('bio','').strip()
    if not all([fn,ln,em,pw]): return jsonify({'error':'All fields required'}),400
    if len(pw)<8: return jsonify({'error':'Password min 8 chars'}),400
    if Q('SELECT id FROM users WHERE email=?',(em,),one=True): return jsonify({'error':'Email in use'}),409
    colors=['#6B8CFF','#34D399','#FBB040','#F87171','#A78BFA','#38BDF8']
    uid=nid()
    X('INSERT INTO users(id,first_name,last_name,email,password,role,bio,color,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
      (uid,fn,ln,em,hash_pw(pw),rl,bio,colors[len(Q('SELECT id FROM users'))%6],now()))
    return jsonify(R(Q('SELECT id,first_name,last_name,email,role,status,bio,color,created_at FROM users WHERE id=?',(uid,),one=True))),201

@app.route('/api/users/<uid_>',methods=['PUT'])
@auth()
def upd_user(uid_):
    u=cu()
    if u['id']!=uid_ and u['role']!='administrator': return jsonify({'error':'Forbidden'}),403
    d=request.get_json() or {}
    fn=d.get('first_name','').strip(); ln=d.get('last_name','').strip()
    em=d.get('email','').strip().lower(); bio=d.get('bio','').strip()
    rl=d.get('role'); pw=d.get('password','')
    if not all([fn,ln,em]): return jsonify({'error':'Required fields missing'}),400
    if Q('SELECT id FROM users WHERE email=? AND id!=?',(em,uid_),one=True): return jsonify({'error':'Email in use'}),409
    if rl and u['role']=='administrator':
        X('UPDATE users SET first_name=?,last_name=?,email=?,bio=?,role=? WHERE id=?',(fn,ln,em,bio,rl,uid_))
    else:
        X('UPDATE users SET first_name=?,last_name=?,email=?,bio=? WHERE id=?',(fn,ln,em,bio,uid_))
    if pw:
        if len(pw)<8: return jsonify({'error':'Password min 8 chars'}),400
        X('UPDATE users SET password=? WHERE id=?',(hash_pw(pw),uid_))
    return jsonify(R(Q('SELECT id,first_name,last_name,email,role,status,bio,color,created_at FROM users WHERE id=?',(uid_,),one=True)))

@app.route('/api/users/<uid_>/status',methods=['PATCH'])
@auth(['administrator'])
def toggle_status(uid_):
    if uid_==cu()['id']: return jsonify({'error':"Can't change your own status"}),400
    u=R(Q('SELECT id,status FROM users WHERE id=?',(uid_,),one=True))
    if not u: return jsonify({'error':'Not found'}),404
    ns='suspended' if u['status']=='active' else 'active'
    X('UPDATE users SET status=? WHERE id=?',(ns,uid_))
    return jsonify({'status':ns})

@app.route('/api/users/<uid_>',methods=['DELETE'])
@auth(['administrator'])
def del_user(uid_):
    if uid_==cu()['id']: return jsonify({'error':"Can't delete yourself"}),400
    X('DELETE FROM users WHERE id=?',(uid_,))
    return jsonify({'ok':True})

@app.route('/api/users/<uid_>/password',methods=['PUT'])
@auth()
def chg_pw(uid_):
    u=cu()
    if u['id']!=uid_ and u['role']!='administrator': return jsonify({'error':'Forbidden'}),403
    d=request.get_json() or {}; cp=d.get('current_password',''); np=d.get('new_password','')
    if len(np)<8: return jsonify({'error':'Min 8 chars'}),400
    stored=R(Q('SELECT password FROM users WHERE id=?',(uid_,),one=True))
    if not stored: return jsonify({'error':'Not found'}),404
    if u['role']!='administrator':
        if not check_pw(cp,stored['password']): return jsonify({'error':'Current password incorrect'}),400
    X('UPDATE users SET password=? WHERE id=?',(hash_pw(np),uid_))
    return jsonify({'ok':True})

# ── CATEGORIES ─────────────────────────────────────
@app.route('/api/categories')
def list_cats():
    cs=Rs(Q('SELECT * FROM categories ORDER BY name'))
    pc={r['category_id']:r['cnt'] for r in Q('SELECT category_id,COUNT(*) as cnt FROM posts GROUP BY category_id')}
    for c in cs: c['post_count']=pc.get(c['id'],0)
    return jsonify(cs)

@app.route('/api/categories',methods=['POST'])
@auth(['administrator','editor'])
def create_cat():
    d=request.get_json() or {}; nm=d.get('name','').strip()
    if not nm: return jsonify({'error':'Name required'}),400
    if Q('SELECT id FROM categories WHERE name=?',(nm,),one=True): return jsonify({'error':'Already exists'}),409
    sl=re.sub(r'[^\w-]','-',nm.lower()).strip('-') or 'cat'
    cid=nid()
    X('INSERT INTO categories(id,name,slug,description,color,created_at) VALUES(?,?,?,?,?,?)',
      (cid,nm,sl,d.get('description',''),d.get('color','#6B8CFF'),now()))
    return jsonify(R(Q('SELECT * FROM categories WHERE id=?',(cid,),one=True))),201

@app.route('/api/categories/<cid>',methods=['PUT'])
@auth(['administrator','editor'])
def upd_cat(cid):
    d=request.get_json() or {}; nm=d.get('name','').strip()
    if not nm: return jsonify({'error':'Name required'}),400
    if Q('SELECT id FROM categories WHERE name=? AND id!=?',(nm,cid),one=True): return jsonify({'error':'Name in use'}),409
    sl=re.sub(r'[^\w-]','-',nm.lower()).strip('-') or 'cat'
    X('UPDATE categories SET name=?,slug=?,description=?,color=? WHERE id=?',
      (nm,sl,d.get('description',''),d.get('color','#6B8CFF'),cid))
    return jsonify(R(Q('SELECT * FROM categories WHERE id=?',(cid,),one=True)))

@app.route('/api/categories/<cid>',methods=['DELETE'])
@auth(['administrator'])
def del_cat(cid):
    X('DELETE FROM categories WHERE id=?',(cid,)); return jsonify({'ok':True})

# ── POSTS ──────────────────────────────────────────
@app.route('/api/posts')
@auth()
def list_posts():
    u=cu(); page=max(1,int(request.args.get('page',1))); limit=min(100,int(request.args.get('limit',50)))
    status=request.args.get('status',''); cat=request.args.get('category',''); search=request.args.get('search','').strip()
    where,args=[],[]
    if u['role']=='author': where.append('p.author_id=?'); args.append(u['id'])
    if status: where.append('p.status=?'); args.append(status)
    if cat: where.append('p.category_id=?'); args.append(cat)
    if search: where.append('(p.title LIKE ? OR p.excerpt LIKE ?)'); args+=[f'%{search}%',f'%{search}%']
    ws='WHERE '+' AND '.join(where) if where else ''
    total=Q(f'SELECT COUNT(*) as n FROM posts p {ws}',args,one=True)['n']
    ps=Rs(Q(f'SELECT p.* FROM posts p {ws} ORDER BY p.updated_at DESC LIMIT ? OFFSET ?',args+[limit,(page-1)*limit]))
    for p in ps: enrich(p)
    return jsonify({'posts':ps,'total':total,'page':page,'limit':limit})

@app.route('/api/posts/<pid>')
@auth()
def get_post(pid):
    u=cu(); p=R(Q('SELECT * FROM posts WHERE id=?',(pid,),one=True))
    if not p: return jsonify({'error':'Not found'}),404
    if u['role']=='author' and p['author_id']!=u['id']: return jsonify({'error':'Forbidden'}),403
    return jsonify(enrich(p))

@app.route('/api/posts',methods=['POST'])
@auth()
def create_post():
    u=cu(); d=request.get_json() or {}
    title=d.get('title','').strip() or 'Untitled'; pid=nid(); ns=d.get('status','draft')
    X('''INSERT INTO posts(id,title,slug,body,excerpt,status,author_id,category_id,
         meta_title,meta_desc,allow_comments,published_at,created_at,updated_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
      (pid,title,mslug(title),d.get('body',''),d.get('excerpt',''),ns,u['id'],
       d.get('category_id') or None,d.get('meta_title',''),d.get('meta_desc',''),
       1 if d.get('allow_comments',True) else 0,
       now() if ns=='published' else None,now(),now()))
    for t in d.get('tags',[]):
        t=t.strip().lower()
        if t: X('INSERT OR IGNORE INTO post_tags(post_id,tag) VALUES(?,?)',(pid,t))
    if ns=='pending':
        for ed in Q("SELECT id FROM users WHERE role IN ('administrator','editor') AND id!=?",(u['id'],)):
            notif(ed['id'],f'<strong>{u["first_name"]} {u["last_name"]}</strong> submitted <strong>"{title}"</strong> for review',
                  'file-text','rgba(107,140,255,.12)','content')
    return jsonify(enrich(R(Q('SELECT * FROM posts WHERE id=?',(pid,),one=True)))),201

@app.route('/api/posts/<pid>',methods=['PUT'])
@auth()
def upd_post(pid):
    u=cu(); p=R(Q('SELECT * FROM posts WHERE id=?',(pid,),one=True))
    if not p: return jsonify({'error':'Not found'}),404
    if u['role'] not in ('administrator','editor') and p['author_id']!=u['id']: return jsonify({'error':'Forbidden'}),403
    d=request.get_json() or {}
    title=d.get('title','').strip() or p['title']
    slug=mslug(title,pid) if title!=p['title'] else p['slug']
    old_st=p['status']; new_st=d.get('status',old_st)
    pub_at=p['published_at']
    if new_st=='published' and not pub_at: pub_at=now()
    X('''UPDATE posts SET title=?,slug=?,body=?,excerpt=?,status=?,category_id=?,
         meta_title=?,meta_desc=?,allow_comments=?,published_at=?,updated_at=? WHERE id=?''',
      (title,slug,d.get('body',p['body']),d.get('excerpt',p['excerpt']),new_st,
       d.get('category_id') or None,d.get('meta_title',p['meta_title']),d.get('meta_desc',p['meta_desc']),
       1 if d.get('allow_comments',bool(p['allow_comments'])) else 0,pub_at,now(),pid))
    if 'tags' in d:
        X('DELETE FROM post_tags WHERE post_id=?',(pid,))
        for t in d['tags']:
            t=t.strip().lower()
            if t: X('INSERT OR IGNORE INTO post_tags(post_id,tag) VALUES(?,?)',(pid,t))
    author=R(Q('SELECT id,first_name,last_name FROM users WHERE id=?',(p['author_id'],),one=True))
    if new_st=='pending' and old_st!='pending':
        for ed in Q("SELECT id FROM users WHERE role IN ('administrator','editor') AND id!=?",(u['id'],)):
            notif(ed['id'],f'<strong>{author["first_name"]} {author["last_name"]}</strong> submitted <strong>"{title}"</strong> for review',
                  'file-text','rgba(107,140,255,.12)','content')
    elif new_st=='published' and old_st!='published' and author and author['id']!=u['id']:
        notif(author['id'],f'Your post <strong>"{title}"</strong> was approved and published','check-circle','rgba(52,211,153,.12)','content')
    elif new_st=='draft' and old_st=='pending' and author and author['id']!=u['id']:
        notif(author['id'],f'Your post <strong>"{title}"</strong> was sent back for revision','alert-circle','rgba(248,113,113,.12)','content')
    return jsonify(enrich(R(Q('SELECT * FROM posts WHERE id=?',(pid,),one=True))))

@app.route('/api/posts/<pid>',methods=['DELETE'])
@auth()
def del_post(pid):
    u=cu(); p=R(Q('SELECT * FROM posts WHERE id=?',(pid,),one=True))
    if not p: return jsonify({'error':'Not found'}),404
    if u['role'] not in ('administrator','editor') and p['author_id']!=u['id']: return jsonify({'error':'Forbidden'}),403
    X('DELETE FROM posts WHERE id=?',(pid,)); return jsonify({'ok':True})

@app.route('/api/posts/<pid>/view',methods=['POST'])
def inc_view(pid):
    X('UPDATE posts SET views=views+1 WHERE id=?',(pid,)); return jsonify({'ok':True})

# ── COMMENTS ───────────────────────────────────────
@app.route('/api/comments')
@auth(['administrator','editor'])
def list_comments():
    s=request.args.get('status','')
    w,a=('WHERE c.status=?',[s]) if s else ('','')
    return jsonify(Rs(Q(f'SELECT c.*,p.title as post_title FROM comments c LEFT JOIN posts p ON c.post_id=p.id {w} ORDER BY c.created_at DESC',a)))

@app.route('/api/posts/<pid>/comments',methods=['POST'])
def submit_comment(pid):
    p=Q('SELECT id,allow_comments FROM posts WHERE id=? AND status="published"',(pid,),one=True)
    if not p: return jsonify({'error':'Post not found'}),404
    if not p['allow_comments']: return jsonify({'error':'Comments disabled'}),403
    d=request.get_json() or {}
    nm=d.get('name','').strip(); em=d.get('email','').strip(); body=d.get('body','').strip()
    if not all([nm,em,body]): return jsonify({'error':'All fields required'}),400
    cid=nid(); st='pending' if cfg('comment_mod','1')=='1' else 'approved'
    X('INSERT INTO comments(id,post_id,visitor_name,visitor_email,body,status,created_at) VALUES(?,?,?,?,?,?,?)',
      (cid,pid,nm,em,body,st,now()))
    pr=R(Q('SELECT author_id,title FROM posts WHERE id=?',(pid,),one=True))
    if pr: notif(pr['author_id'],f'New comment on <strong>"{pr["title"]}"</strong> from {nm}','message-square','rgba(251,176,64,.12)','comments')
    return jsonify(R(Q('SELECT * FROM comments WHERE id=?',(cid,),one=True))),201

@app.route('/api/comments/<cid>/moderate',methods=['PATCH'])
@auth(['administrator','editor'])
def mod_comment(cid):
    d=request.get_json() or {}; st=d.get('status','')
    if st not in ('approved','rejected'): return jsonify({'error':'Invalid status'}),400
    X('UPDATE comments SET status=?,moderated_by=?,moderated_at=? WHERE id=?',(st,cu()['id'],now(),cid))
    return jsonify(R(Q('SELECT * FROM comments WHERE id=?',(cid,),one=True)))

@app.route('/api/comments/<cid>',methods=['DELETE'])
@auth(['administrator','editor'])
def del_comment(cid):
    X('DELETE FROM comments WHERE id=?',(cid,)); return jsonify({'ok':True})

# ── MEDIA ──────────────────────────────────────────
@app.route('/api/media')
@auth()
def list_media():
    u=cu(); tp=request.args.get('type',''); search=request.args.get('search','').strip()
    where,args=[],[]
    if u['role']=='author': where.append('m.uploaded_by=?'); args.append(u['id'])
    if search: where.append('m.original_name LIKE ?'); args.append(f'%{search}%')
    if tp=='image': where.append("m.mime_type LIKE 'image/%'")
    elif tp=='document': where.append("(m.mime_type LIKE '%pdf%' OR m.mime_type LIKE '%word%')")
    elif tp=='video': where.append("m.mime_type LIKE 'video/%'")
    ws='WHERE '+'AND '.join(where) if where else ''
    ms=Rs(Q(f'SELECT m.*,u.first_name,u.last_name FROM media m LEFT JOIN users u ON m.uploaded_by=u.id {ws} ORDER BY m.created_at DESC',args))
    for m in ms: m['url']=f'/uploads/{m["filename"]}'
    return jsonify(ms)

@app.route('/api/media',methods=['POST'])
@auth()
def upload_media():
    if 'file' not in request.files: return jsonify({'error':'No file'}),400
    f=request.files['file']
    ext=f.filename.rsplit('.',1)[-1].lower() if '.' in f.filename else ''
    if ext not in ALLOWED_EXT: return jsonify({'error':f'.{ext} not allowed'}),400
    data=f.read()
    if len(data)>MAX_UPLOAD: return jsonify({'error':'Exceeds 20MB limit'}),413
    safe=f'{secrets.token_hex(12)}.{ext}'
    with open(os.path.join(UPLOADS_DIR,safe),'wb') as fh: fh.write(data)
    mime=f.mimetype or mimetypes.guess_type(f.filename)[0] or 'application/octet-stream'
    mid=nid()
    X('INSERT INTO media(id,filename,original_name,mime_type,size,uploaded_by,created_at) VALUES(?,?,?,?,?,?,?)',
      (mid,safe,f.filename,mime,len(data),cu()['id'],now()))
    m=R(Q('SELECT * FROM media WHERE id=?',(mid,),one=True)); m['url']=f'/uploads/{safe}'
    return jsonify(m),201

@app.route('/api/media/<mid>/alt',methods=['PATCH'])
@auth()
def upd_alt(mid):
    X('UPDATE media SET alt_text=? WHERE id=?',((request.get_json() or {}).get('alt_text',''),mid))
    return jsonify({'ok':True})

@app.route('/api/media/<mid>',methods=['DELETE'])
@auth()
def del_media(mid):
    u=cu(); m=R(Q('SELECT * FROM media WHERE id=?',(mid,),one=True))
    if not m: return jsonify({'error':'Not found'}),404
    if u['role'] not in ('administrator','editor') and m['uploaded_by']!=u['id']: return jsonify({'error':'Forbidden'}),403
    try:
        p=os.path.join(UPLOADS_DIR,m['filename'])
        if os.path.exists(p): os.remove(p)
    except: pass
    X('DELETE FROM media WHERE id=?',(mid,)); return jsonify({'ok':True})

@app.route('/uploads/<filename>')
def serve_upload(filename): return send_from_directory(UPLOADS_DIR,filename)

# ── NOTIFICATIONS ──────────────────────────────────
@app.route('/api/notifications')
@auth()
def list_notifs():
    return jsonify(Rs(Q('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50',(cu()['id'],))))

@app.route('/api/notifications/read-all',methods=['POST'])
@auth()
def read_all_notifs():
    X('UPDATE notifications SET is_read=1 WHERE user_id=?',(cu()['id'],)); return jsonify({'ok':True})

@app.route('/api/notifications/<nid_>/read',methods=['PATCH'])
@auth()
def read_notif(nid_):
    X('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?',(nid_,cu()['id'])); return jsonify({'ok':True})

# ── ANALYTICS ──────────────────────────────────────
@app.route('/api/analytics')
@auth()
def analytics():
    ps=Rs(Q('SELECT status,views FROM posts'))
    total_v=sum(p['views'] for p in ps)
    by_st={}
    for p in ps: by_st[p['status']]=by_st.get(p['status'],0)+1
    cs=Rs(Q('SELECT status FROM comments')); c_cnt={'total':len(cs)}
    for c in cs: c_cnt[c['status']]=c_cnt.get(c['status'],0)+1
    yr=datetime.now().year; monthly=[0]*12
    for r in Q("SELECT created_at FROM posts WHERE created_at LIKE ?",(f'{yr}%',)):
        try: monthly[int(r['created_at'][5:7])-1]+=1
        except: pass
    weekly=[0]*7
    for r in Q("SELECT created_at FROM posts"):
        try:
            ts=datetime.fromisoformat(r['created_at'].replace('Z','+00:00'))
            diff=(datetime.now(timezone.utc)-ts).days
            if 0<=diff<7: weekly[6-diff]+=1
        except: pass
    top=Rs(Q("SELECT id,title,views FROM posts WHERE status='published' ORDER BY views DESC LIMIT 5"))
    rc={}
    for u in Q('SELECT role FROM users'): rc[u['role']]=rc.get(u['role'],0)+1
    return jsonify({'total_views':total_v,'total_posts':sum(by_st.values()),'posts_by_status':by_st,
                    'users':len(Q('SELECT id FROM users')),'comments':c_cnt,'media':len(Q('SELECT id FROM media')),
                    'monthly':monthly,'weekly':weekly,'top_posts':top,'role_counts':rc})

# ── SERVE FRONTEND ─────────────────────────────────
@app.route('/')
def index(): return send_file(os.path.join(PUBLIC_DIR,'index.html'))

@app.route('/<path:path>')
def catch(path):
    fp=os.path.join(PUBLIC_DIR,path)
    if os.path.isfile(fp): return send_from_directory(PUBLIC_DIR,path)
    return send_file(os.path.join(PUBLIC_DIR,'index.html'))

# ── START ──────────────────────────────────────────
if __name__=='__main__':
    init_db()
    port=int(os.environ.get('PORT',5000))
    print(f'''
  ╔══════════════════════════════════════════════════╗
  ║  EMERGE CMS  —  Server running                   ║
  ║                                                  ║
  ║  Open:  http://localhost:{port:<24}║
  ║  DB:    {os.path.basename(DB_PATH):<41}║
  ╚══════════════════════════════════════════════════╝
''')
    app.run(host='0.0.0.0',port=port,debug=False)