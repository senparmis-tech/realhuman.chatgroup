import os, sqlite3, uuid, time, secrets
from flask import (Flask, g, request, session, redirect, jsonify,
                   send_from_directory, render_template, abort)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "chat.db")
UPLOADS = os.path.join(BASE, "uploads")
os.makedirs(UPLOADS, exist_ok=True)

VALID_SPACES = {"classmates", "realhuman"}
DEFAULT_SPACE = "classmates"
INVITE_CODE = os.environ.get("INVITE_CODE", "classmates")
IMG_EXT = {"png", "jpg", "jpeg", "gif", "webp"}


def secret():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    p = os.path.join(BASE, ".secret")
    if not os.path.exists(p):
        open(p, "w").write(secrets.token_hex(32))
    return open(p).read().strip()


TPL = os.path.join(BASE, "templates")
app = Flask(__name__, template_folder=TPL if os.path.isdir(TPL) else BASE)
app.secret_key = secret()
app.config.update(MAX_CONTENT_LENGTH=16 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30)


@app.after_request
def hdr(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    return r


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB, timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw TEXT);
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY, sender INTEGER, recipient INTEGER,
      body TEXT, file TEXT, fname TEXT, mime TEXT, ts REAL);""")
    c.executescript("""
    CREATE TABLE IF NOT EXISTS groups(id INTEGER PRIMARY KEY, name TEXT);
    CREATE TABLE IF NOT EXISTS gmembers(gid INTEGER, uid INTEGER, last_read INTEGER DEFAULT 0, PRIMARY KEY(gid,uid));
    CREATE TABLE IF NOT EXISTS reactions(mid INTEGER, uid INTEGER, emoji TEXT, PRIMARY KEY(mid,uid,emoji));""")
    cols = lambda t: {r[1] for r in c.execute(f"PRAGMA table_info({t})")}
    for col, typ in [("is_admin", "INTEGER DEFAULT 0"), ("last_seen", "REAL DEFAULT 0"),
                     ("typing_to", "INTEGER"), ("typing_ts", "REAL DEFAULT 0"),
                     ("can_rename", "INTEGER DEFAULT 0"), ("can_upload", "INTEGER DEFAULT 1"),
                     ("can_unsend", "INTEGER DEFAULT 1")]:
        if col not in cols("users"):
            c.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
    for col, typ in [("edited", "INTEGER DEFAULT 0"), ("deleted", "INTEGER DEFAULT 0"),
                     ("reply_to", "INTEGER"), ("grp", "INTEGER"), ("read_ts", "REAL"), ("upd", "REAL DEFAULT 0"),
                     ("space", "TEXT DEFAULT 'classmates'")]:
        if col not in cols("messages"):
            c.execute(f"ALTER TABLE messages ADD COLUMN {col} {typ}")
    if "space" not in cols("groups"):
        c.execute("ALTER TABLE groups ADD COLUMN space TEXT DEFAULT 'classmates'")
    c.execute("DELETE FROM messages WHERE deleted=1")  # old "deleted" placeholders: remove all trace
    c.execute("UPDATE messages SET upd=ts WHERE upd=0 OR upd IS NULL")
    adm_row = c.execute("SELECT id FROM users WHERE username='admin' COLLATE NOCASE").fetchone()
    if not adm_row:
        c.execute("INSERT INTO users(username, pw, is_admin, can_rename, can_upload, can_unsend) VALUES(?,?,1,1,1,1)",
                  ('admin', generate_password_hash('123admin')))
    else:
        c.execute("UPDATE users SET is_admin=1 WHERE id=?", (adm_row[0],))
    if not c.execute("SELECT 1 FROM users WHERE is_admin=1").fetchone():
        c.execute("UPDATE users SET is_admin=1 WHERE id=(SELECT MIN(id) FROM users)")
    c.commit(); c.close()


init_db()


def me():
    return session.get("uid")


def current_space():
    return session.get("space", DEFAULT_SPACE)


def need_login():
    if not me():
        abort(401)
    r = db().execute("SELECT 1 FROM users WHERE id=?", (me(),)).fetchone()
    if not r:
        session.clear()
        abort(401)
    db().execute("UPDATE users SET last_seen=? WHERE id=?", (time.time(), me()))
    db().commit()


def gm(g):
    if not db().execute("SELECT 1 FROM gmembers WHERE gid=? AND uid=?", (g, me())).fetchone():
        abort(403)


def admin_only():
    need_login()
    if not is_admin():
        abort(403)


def can(p):
    r = db().execute(f"SELECT is_admin,{p} FROM users WHERE id=?", (me(),)).fetchone()
    return bool(r and (r["is_admin"] or r[p]))


def set_name(uid, name):
    name = name.strip()[:30]
    if not name:
        abort(400)
    if db().execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE AND id<>?", (name, uid)).fetchone():
        abort(409)
    db().execute("UPDATE users SET username=? WHERE id=?", (name, uid))
    db().commit()


def is_admin():
    r = db().execute("SELECT is_admin FROM users WHERE id=?", (me(),)).fetchone()
    return bool(r and r["is_admin"])


fails = {}  # ip -> (count, first_ts)


def throttled():
    n, t = fails.get(request.remote_addr, (0, time.time()))
    if time.time() - t > 600:
        fails.pop(request.remote_addr, None)
        return False
    return n >= 8


@app.route("/")
def index():
    if not me():
        return render_template("index.html", user=None, error=request.args.get("e"))
    r = db().execute("SELECT username FROM users WHERE id=?", (me(),)).fetchone()
    if not r:
        session.clear()
        return redirect("/")
    return render_template("index.html", user={"id": me(), "name": r["username"], "admin": is_admin(), "rename": can("can_rename"), "space": current_space()})


@app.route("/auth", methods=["POST"])
def auth():
    if throttled():
        return redirect("/?e=Too many attempts, try again in 10 minutes")
    name = request.form.get("username", "").strip()[:30]
    pw = request.form.get("password", "")
    invite = request.form.get("invite", "").strip().lower()
    if not name or len(pw) < 4:
        return redirect("/?e=Enter a username and a password (4+ characters)")
    row = db().execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (name,)).fetchone()
    bad = None
    target_space = invite if invite in VALID_SPACES else DEFAULT_SPACE
    if row:
        if not check_password_hash(row["pw"], pw):
            bad = "Wrong password"
        elif invite and invite not in VALID_SPACES:
            bad = "Invalid code. Use 'classmates' or 'realhuman'"
    elif invite not in VALID_SPACES:
        bad = "New account needs invite code: 'classmates' or 'realhuman'"
    else:
        first = not db().execute("SELECT 1 FROM users").fetchone()
        cur = db().execute("INSERT INTO users(username,pw,is_admin) VALUES(?,?,?)",
                           (name, generate_password_hash(pw), 1 if first else 0))
        db().commit()
        row = db().execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    if bad:
        n, t = fails.get(request.remote_addr, (0, time.time()))
        fails[request.remote_addr] = (n + 1, t)
        return redirect("/?e=" + bad)
    session.clear()
    session.permanent = True
    session["uid"] = row["id"]
    session["space"] = target_space
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/api/users")
def users():
    need_login()
    now = time.time()
    sp = current_space()
    rows = db().execute("""
      SELECT u.id, u.username, u.last_seen,
        (SELECT COUNT(*) FROM messages WHERE sender=u.id AND recipient=? AND read_ts IS NULL AND deleted=0 AND (space=? OR space IS NULL)) AS unread
      FROM users u WHERE u.id<>? ORDER BY u.username""", (me(), sp, me())).fetchall()
    return jsonify([dict(id=r["id"], username=r["username"], unread=r["unread"],
                         online=now - (r["last_seen"] or 0) < 15) for r in rows])


def get_reactions_for_msgs(mids):
    if not mids:
        return {}
    q = f"SELECT r.mid, r.emoji, r.uid, u.username FROM reactions r JOIN users u ON u.id=r.uid WHERE r.mid IN ({','.join('?'*len(mids))})"
    res = {}
    for r in db().execute(q, mids).fetchall():
        mid = r["mid"]
        if mid not in res:
            res[mid] = {}
        emo = r["emoji"]
        if emo not in res[mid]:
            res[mid][emo] = {"count": 0, "users": [], "has_me": False}
        res[mid][emo]["count"] += 1
        res[mid][emo]["users"].append(r["username"])
        if r["uid"] == me():
            res[mid][emo]["has_me"] = True
    return res


def row_json(r, rx_map=None):
    ext = (r["fname"] or "").rsplit(".", 1)[-1].lower()
    dele = bool(r["deleted"])
    rx = (rx_map.get(r["id"]) if rx_map else {}) or {}
    return dict(id=r["id"], sender=r["sender"], body="" if dele else r["body"],
                file=None if dele else r["file"], fname=r["fname"],
                img=(not dele) and ext in IMG_EXT, ts=r["ts"], edited=bool(r["edited"]),
                deleted=dele, name=r["name"], reply_to=r["reply_to"], rbody=r["rbody"],
                read=r["read_ts"] is not None, reactions=rx)


MSG_SQL = """SELECT m.*, (SELECT username FROM users WHERE id=m.sender) AS name, (SELECT CASE WHEN r.deleted=1 THEN NULL
              ELSE COALESCE(NULLIF(r.body,''), '📎 '||r.fname) END
              FROM messages r WHERE r.id=m.reply_to) AS rbody FROM messages m """
PAIR = "((m.sender=? AND m.recipient=?) OR (m.sender=? AND m.recipient=?))"


@app.route("/api/messages")
def messages():
    need_login()
    other = int(request.args.get("with", 0))
    after = int(request.args.get("after", 0))
    since = float(request.args.get("since", 0))
    now = time.time()
    d = db()
    sp = current_space()
    g_ = request.args.get("g", type=int)
    if g_:
        gm(g_)
        rows = d.execute(MSG_SQL + "WHERE (m.id>? OR m.upd>?) AND m.grp=? AND (m.space=? OR m.space IS NULL) ORDER BY m.id", (after, since, g_, sp)).fetchall()
        ids = [r[0] for r in d.execute("SELECT id FROM messages WHERE grp=? AND (space=? OR space IS NULL)", (g_, sp))]
        d.execute("UPDATE gmembers SET last_read=? WHERE gid=? AND uid=?", (max(ids, default=0), g_, me()))
        d.commit()
        rx_map = get_reactions_for_msgs([r["id"] for r in rows])
        return jsonify(msgs=[row_json(r, rx_map) for r in rows], ids=ids, now=now - 1, typing=False)
    d.execute("UPDATE messages SET read_ts=?, upd=? WHERE sender=? AND recipient=? AND read_ts IS NULL AND (space=? OR space IS NULL)",
              (now, now, other, me(), sp))
    d.commit()
    rows = d.execute(MSG_SQL + "WHERE (m.id>? OR m.upd>?) AND " + PAIR + " AND (m.space=? OR m.space IS NULL) ORDER BY m.id",
                     (after, since, me(), other, other, me(), sp)).fetchall()
    t = d.execute("SELECT typing_to, typing_ts FROM users WHERE id=?", (other,)).fetchone()
    typing = bool(t and t["typing_to"] == me() and now - (t["typing_ts"] or 0) < 4)
    ids = [r[0] for r in d.execute("SELECT m.id FROM messages m WHERE " + PAIR + " AND (m.space=? OR m.space IS NULL)", (me(), other, other, me(), sp))]
    rx_map = get_reactions_for_msgs([r["id"] for r in rows])
    return jsonify(msgs=[row_json(r, rx_map) for r in rows], ids=ids, now=now - 1, typing=typing)


@app.route("/api/send", methods=["POST"])
def send():
    need_login()
    other = request.form.get("to", 0, type=int)
    g_ = request.form.get("g", type=int)
    if g_:
        gm(g_)
        other = None
    elif other == me() or not db().execute("SELECT 1 FROM users WHERE id=?", (other,)).fetchone():
        abort(400)
    body = request.form.get("body", "").strip()[:4000]
    reply = request.form.get("reply_to", type=int)
    ok = (db().execute("SELECT 1 FROM messages WHERE id=? AND grp=?", (reply, g_)) if g_ else
          db().execute("SELECT 1 FROM messages m WHERE m.id=? AND " + PAIR, (reply, me(), other, other, me()))
          ) if reply else None
    if reply and not ok.fetchone():
        reply = None
    stored = fname = mime = None
    f = request.files.get("file")
    if f and f.filename and not can("can_upload"):
        abort(403)
    if f and f.filename:
        fname = secure_filename(f.filename) or "file"
        stored = uuid.uuid4().hex + "_" + fname
        f.save(os.path.join(UPLOADS, stored))
        mime = f.mimetype
    if not body and not stored:
        abort(400)
    now = time.time()
    sp = current_space()
    db().execute("""INSERT INTO messages(sender,recipient,body,file,fname,mime,ts,upd,reply_to,grp,space)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (me(), other, body, stored, fname, mime, now, now, reply, g_, sp))
    db().execute("UPDATE users SET typing_to=NULL WHERE id=?", (me(),))
    db().commit()
    return jsonify(ok=True)


def own_msg(mid):
    r = db().execute("SELECT * FROM messages WHERE id=? AND sender=?", (mid, me())).fetchone()
    if not r or r["deleted"]:
        abort(404)
    return r


@app.route("/api/edit/<int:mid>", methods=["POST"])
def edit(mid):
    need_login()
    own_msg(mid)
    body = request.form.get("body", "").strip()[:4000]
    if not body:
        abort(400)
    db().execute("UPDATE messages SET body=?, edited=1, upd=? WHERE id=?", (body, time.time(), mid))
    db().commit()
    return jsonify(ok=True)


def kill_msg(r):
    if r["file"]:
        try:
            os.remove(os.path.join(UPLOADS, r["file"]))
        except OSError:
            pass
    db().execute("DELETE FROM reactions WHERE mid=?", (r["id"],))
    db().execute("UPDATE messages SET reply_to=NULL WHERE reply_to=?", (r["id"],))
    db().execute("DELETE FROM messages WHERE id=?", (r["id"],))


@app.route("/api/react/<int:mid>", methods=["POST"])
def react(mid):
    need_login()
    emoji = request.form.get("emoji", "").strip()[:10]
    if not emoji:
        abort(400)
    d = db()
    m = d.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if not m or m["deleted"]:
        abort(404)
    if m["grp"]:
        gm(m["grp"])
    elif m["sender"] != me() and m["recipient"] != me():
        abort(403)
    existing = d.execute("SELECT 1 FROM reactions WHERE mid=? AND uid=? AND emoji=?", (mid, me(), emoji)).fetchone()
    if existing:
        d.execute("DELETE FROM reactions WHERE mid=? AND uid=? AND emoji=?", (mid, me(), emoji))
    else:
        d.execute("INSERT OR REPLACE INTO reactions(mid, uid, emoji) VALUES(?,?,?)", (mid, me(), emoji))
    now = time.time()
    d.execute("UPDATE messages SET upd=? WHERE id=?", (now, mid))
    d.commit()
    return jsonify(ok=True)


def deletable_msg(mid):
    r = db().execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if not r or r["deleted"]:
        abort(404)
    if r["sender"] == me() and can("can_unsend"):
        return r
    if is_admin():
        return r
    abort(403)


@app.route("/api/delete/<int:mid>", methods=["POST"])
def delete(mid):
    need_login()
    r = deletable_msg(mid)
    kill_msg(r)
    db().commit()
    return jsonify(ok=True)


@app.route("/api/typing", methods=["POST"])
def typing():
    need_login()
    db().execute("UPDATE users SET typing_to=?, typing_ts=? WHERE id=?",
                 (request.form.get("to", type=int), time.time(), me()))
    db().commit()
    return jsonify(ok=True)


@app.route("/api/search")
def search():
    need_login()
    other = request.args.get("with", 0, type=int)
    g_ = request.args.get("g", type=int)
    if g_:
        gm(g_)
    q = request.args.get("q", "").strip()[:100]
    if not q:
        return jsonify([])
    like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    sp = current_space()
    cond, args = ("m.grp=? AND (m.space=? OR m.space IS NULL)", (g_, sp)) if g_ else (PAIR + " AND (m.space=? OR m.space IS NULL)", (me(), other, other, me(), sp))
    rows = db().execute(MSG_SQL + "WHERE m.body LIKE ? ESCAPE '\\' AND " + cond +
                        " ORDER BY m.id DESC LIMIT 50", (like,) + args).fetchall()
    rx_map = get_reactions_for_msgs([r["id"] for r in rows])
    return jsonify([row_json(r, rx_map) for r in rows])


@app.route("/api/admin/users")
def admin_users():
    admin_only()
    rows = db().execute("SELECT id, username, is_admin, can_rename, can_upload, can_unsend FROM users ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/rename", methods=["POST"])
def rename():
    need_login()
    if not can("can_rename"):
        abort(403)
    set_name(me(), request.form.get("name", ""))
    return jsonify(ok=True)


@app.route("/api/admin/set/<int:uid>", methods=["POST"])
def admin_set(uid):
    admin_only()
    f, v = request.form.get("field"), request.form.get("value", "")
    if f == "name":
        set_name(uid, v)
    elif f == "pw":
        if len(v) < 4:
            abort(400)
        db().execute("UPDATE users SET pw=? WHERE id=?", (generate_password_hash(v), uid))
        db().commit()
    elif f in ("is_admin", "can_rename", "can_upload", "can_unsend"):
        val = 1 if v == "1" else 0
        if f == "is_admin" and not val and not db().execute(
                "SELECT 1 FROM users WHERE is_admin=1 AND id<>?", (uid,)).fetchone():
            abort(400)  # always keep at least one admin
        db().execute(f"UPDATE users SET {f}=? WHERE id=?", (val, uid))
        db().commit()
    else:
        abort(400)
    return jsonify(ok=True)


@app.route("/api/admin/create_user", methods=["POST"])
def admin_create_user():
    admin_only()
    name = request.form.get("username", "").strip()[:30]
    pw = request.form.get("password", "")
    is_adm = 1 if request.form.get("is_admin") in ("1", "true", "on") else 0
    if not name:
        return jsonify(ok=False, error="Username is required"), 400
    if len(pw) < 4:
        return jsonify(ok=False, error="Password must be at least 4 characters"), 400
    if db().execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE", (name,)).fetchone():
        return jsonify(ok=False, error="Username already taken"), 409
    cur = db().execute(
        "INSERT INTO users(username, pw, is_admin, can_rename, can_upload, can_unsend) VALUES(?,?,?,?,1,1)",
        (name, generate_password_hash(pw), is_adm, 1 if is_adm else 0)
    )
    db().commit()
    return jsonify(ok=True, id=cur.lastrowid, username=name)


@app.route("/api/admin/delete_user/<int:uid>", methods=["POST"])
def admin_delete_user(uid):
    need_login()
    if not is_admin() or uid == me():
        abort(403)
    for r in db().execute("SELECT * FROM messages WHERE (sender=? OR recipient=?) AND file IS NOT NULL",
                          (uid, uid)).fetchall():
        kill_msg(r)
    db().execute("DELETE FROM messages WHERE sender=? OR recipient=?", (uid, uid))
    db().execute("DELETE FROM gmembers WHERE uid=?", (uid,))
    db().execute("DELETE FROM users WHERE id=?", (uid,))
    db().commit()
    return jsonify(ok=True)


@app.route("/api/delete_account", methods=["POST"])
def delete_account():
    need_login()
    uid = me()
    if is_admin() and not db().execute("SELECT 1 FROM users WHERE is_admin=1 AND id<>?", (uid,)).fetchone():
        abort(400)
    for r in db().execute("SELECT * FROM messages WHERE (sender=? OR recipient=?) AND file IS NOT NULL",
                          (uid, uid)).fetchall():
        kill_msg(r)
    db().execute("DELETE FROM messages WHERE sender=? OR recipient=?", (uid, uid))
    db().execute("DELETE FROM gmembers WHERE uid=?", (uid,))
    db().execute("DELETE FROM users WHERE id=?", (uid,))
    db().commit()
    session.clear()
    return jsonify(ok=True)


@app.route("/api/groups")
def groups():
    need_login()
    sp = current_space()
    rows = db().execute("""SELECT g.id, g.name,
      (SELECT COUNT(*) FROM messages m WHERE m.grp=g.id AND m.id>x.last_read AND m.sender<>? AND (m.space=? OR m.space IS NULL)) AS unread
      FROM groups g JOIN gmembers x ON x.gid=g.id WHERE x.uid=? AND (g.space=? OR g.space IS NULL) ORDER BY g.name""", (me(), sp, me(), sp)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/group_create", methods=["POST"])
def group_create():
    admin_only()
    name = request.form.get("name", "").strip()[:40]
    if not name:
        abort(400)
    sp = current_space()
    cur = db().execute("INSERT INTO groups(name, space) VALUES(?,?)", (name, sp))
    db().execute("INSERT INTO gmembers(gid,uid) VALUES(?,?)", (cur.lastrowid, me()))
    db().commit()
    return jsonify(id=cur.lastrowid)


@app.route("/api/admin/group/<int:gid>/members")
def group_members(gid):
    admin_only()
    rows = db().execute("""SELECT u.id, u.username,
      EXISTS(SELECT 1 FROM gmembers x WHERE x.gid=? AND x.uid=u.id) AS member
      FROM users u ORDER BY u.username""", (gid,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/group/<int:gid>/<act>/<int:uid>", methods=["POST"])
def group_member(gid, act, uid):
    admin_only()
    if act == "add" and db().execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone() \
            and db().execute("SELECT 1 FROM groups WHERE id=?", (gid,)).fetchone():
        last = db().execute("SELECT COALESCE(MAX(id),0) FROM messages WHERE grp=?", (gid,)).fetchone()[0]
        db().execute("INSERT OR IGNORE INTO gmembers(gid,uid,last_read) VALUES(?,?,?)", (gid, uid, last))
    elif act == "remove":
        db().execute("DELETE FROM gmembers WHERE gid=? AND uid=?", (gid, uid))
    else:
        abort(400)
    db().commit()
    return jsonify(ok=True)


@app.route("/api/admin/group/<int:gid>/delete", methods=["POST"])
def group_delete(gid):
    admin_only()
    for r in db().execute("SELECT * FROM messages WHERE grp=?", (gid,)).fetchall():
        kill_msg(r)
    db().execute("DELETE FROM gmembers WHERE gid=?", (gid,))
    db().execute("DELETE FROM groups WHERE id=?", (gid,))
    db().commit()
    return jsonify(ok=True)


@app.route("/files/<name>")
def files(name):
    need_login()
    r = db().execute("SELECT fname FROM messages WHERE file=? AND (sender=? OR recipient=? OR grp IN (SELECT gid FROM gmembers WHERE uid=?))",
                     (name, me(), me(), me())).fetchone()
    if not r:
        abort(404)
    ext = (r["fname"] or "").rsplit(".", 1)[-1].lower()
    return send_from_directory(UPLOADS, name, as_attachment=ext not in IMG_EXT,
                               download_name=r["fname"])


if __name__ == "__main__":
    app.run(debug=False)