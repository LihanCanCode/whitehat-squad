import { describe, expect, it } from "vitest";
import { only, scan, scanOne } from "./helpers.js";

const FASTAPI = "from fastapi import FastAPI, Depends\nfrom sqlalchemy.orm import Session\napp = FastAPI()\n";

describe("PY-012 FastAPI routes without auth", () => {
  it("flags a DB-touching route with no auth dependency (medium confidence, high severity)", async () => {
    const code = `${FASTAPI}\n@app.get("/orders")\ndef orders(db: Session = Depends(get_db)):\n    return db.query(Order).all()\n`;
    const f = only(await scanOne(code), "PY-012");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", confidence: "medium", cwe: "CWE-306" });
    expect(f[0]?.evidence[0]?.snippet).toContain("@app.get");
    expect(f[0]?.fix.config).toContain("get_current_user");
    expect(f[0]?.fix.agentPrompt).toContain("orders");
  });
  it("flags routers, writes via session.add/commit and supabase.table", async () => {
    const code =
      "from fastapi import APIRouter\nrouter = APIRouter()\n\n" +
      '@router.post("/items")\nasync def create(item: ItemIn, db: Session = Depends(get_db)):\n    db.add(Item(**item.model_dump(include={"name"})))\n    db.commit()\n\n' +
      '@router.delete("/items/{id}")\nasync def rm(id: int):\n    supabase.table("items").delete().eq("id", id).execute()\n';
    expect(only(await scanOne(code, "routers/items.py"), "PY-012")).toHaveLength(2);
  });
  it("does NOT flag routes with an auth dependency, current_user param, Security or dependencies=[]", async () => {
    const code =
      `${FASTAPI}\n` +
      '@app.get("/a")\ndef a(db: Session = Depends(get_db), user: User = Depends(get_current_user)):\n    return db.query(X).all()\n\n' +
      '@app.get("/b")\ndef b(db: Session = Depends(get_db), current_user: User = None):\n    return db.query(X).all()\n\n' +
      '@app.get("/c", dependencies=[Depends(verify_token)])\ndef c(db: Session = Depends(get_db)):\n    return db.query(X).all()\n\n' +
      '@app.get("/d")\ndef d(db: Session = Depends(get_db), u=Security(scopes_dep, scopes=["x"])):\n    return db.query(X).all()\n\n' +
      '@app.get("/e")\ndef e(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):\n    return db.query(X).all()\n\n' +
      '@app.get("/f")\ndef f(db: Annotated[Session, Depends(get_db)], who: Annotated[User, Depends(require_admin)]):\n    return db.query(X).all()\n';
    expect(only(await scanOne(code), "PY-012")).toEqual([]);
  });
  it("does NOT flag routers or apps that carry a global auth dependency", async () => {
    const router =
      'from fastapi import APIRouter, Depends\nrouter = APIRouter(prefix="/v1", dependencies=[Depends(get_current_user)])\n\n' +
      '@router.get("/x")\ndef x(db=Depends(get_db)):\n    return db.query(X).all()\n';
    expect(only(await scanOne(router, "r.py"), "PY-012")).toEqual([]);
    const project = await scan({
      "main.py": "from fastapi import FastAPI, Depends\napp = FastAPI(dependencies=[Depends(verify_token)])\n",
      "routes.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/x')\ndef x(db):\n    return db.query(X).all()\n",
    });
    expect(only(project, "PY-012")).toEqual([]);
    const included = await scan({
      "main.py": "from fastapi import FastAPI, Depends\napp = FastAPI()\napp.include_router(r, dependencies=[Depends(auth_dep)])\n",
      "routes.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/x')\ndef x(db):\n    return db.query(X).all()\n",
    });
    expect(only(included, "PY-012")).toEqual([]);
  });
  it("excludes login, register, health and docs routes and routes that never touch data", async () => {
    const code =
      `${FASTAPI}\n` +
      '@app.post("/login")\ndef login(db: Session = Depends(get_db)):\n    return db.query(User).first()\n\n' +
      '@app.post("/api/auth/register")\ndef reg_user(db: Session = Depends(get_db)):\n    db.add(User())\n    db.commit()\n\n' +
      '@app.get("/healthz")\ndef healthz(db: Session = Depends(get_db)):\n    return db.execute("select 1")\n\n' +
      '@app.get("/")\ndef root():\n    return {"hello": "world"}\n\n' +
      '@app.get("/version")\ndef version():\n    return {"v": 1}\n';
    expect(only(await scanOne(code), "PY-012")).toEqual([]);
  });
  it("honors whsquad-ignore on the route decorator", async () => {
    const code = `${FASTAPI}\n# whsquad-ignore PY-012\n@app.get("/public-catalog")\ndef cat(db: Session = Depends(get_db)):\n    return db.query(Product).all()\n`;
    expect(only(await scanOne(code), "PY-012")).toEqual([]);
  });
  it("does not treat a file with an auth middleware as unauthenticated", async () => {
    const code =
      `${FASTAPI}\n@app.middleware("http")\nasync def auth_mw(request, call_next):\n    if not request.headers.get("Authorization"):\n        return Response(status_code=401)\n    return await call_next(request)\n\n` +
      '@app.get("/x")\ndef x(db: Session = Depends(get_db)):\n    return db.query(X).all()\n';
    expect(only(await scanOne(code), "PY-012")).toEqual([]);
  });
});

describe("PY-012 Flask routes without auth", () => {
  const FLASK = "from flask import Flask, jsonify, request\nfrom flask_login import login_required, current_user\napp = Flask(__name__)\n";

  it("flags a Flask route that queries the DB without any auth check", async () => {
    const code = `${FLASK}\n@app.route("/users")\ndef users():\n    return jsonify(User.query.all())\n`;
    const f = only(await scanOne(code), "PY-012");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", confidence: "medium" });
    expect(f[0]?.title).toContain("Flask");
  });
  it("flags Flask 2 shortcut routes that commit data", async () => {
    const code = `${FLASK}\n@app.post("/notes")\ndef add():\n    db.session.add(Note(text="x"))\n    db.session.commit()\n    return "ok"\n`;
    expect(only(await scanOne(code), "PY-012")).toHaveLength(1);
  });
  it("does NOT flag login_required / jwt_required, current_user, or abort(401) checks", async () => {
    const code =
      `${FLASK}\n` +
      '@app.route("/a")\n@login_required\ndef a():\n    return jsonify(User.query.all())\n\n' +
      '@app.route("/b")\n@jwt_required()\ndef b():\n    return jsonify(User.query.all())\n\n' +
      '@app.route("/c")\ndef c():\n    return jsonify(Note.query.filter_by(owner=current_user.id).all())\n\n' +
      '@app.route("/d")\ndef d():\n    if not request.headers.get("Authorization"):\n        abort(401)\n    return jsonify(User.query.all())\n';
    expect(only(await scanOne(code), "PY-012")).toEqual([]);
  });
  it("does NOT flag a file with a before_request auth hook or public auth routes", async () => {
    const hook =
      `${FLASK}\n@app.before_request\ndef require_login():\n    if not current_user.is_authenticated:\n        abort(401)\n\n@app.route("/u")\ndef u():\n    return jsonify(User.query.all())\n`;
    expect(only(await scanOne(hook), "PY-012")).toEqual([]);
    const pub = `${FLASK}\n@app.route("/login", methods=["POST"])\ndef do_login():\n    return User.query.first()\n`;
    expect(only(await scanOne(pub), "PY-012")).toEqual([]);
    const pathBased = `${FLASK}\n@app.route("/api/token")\ndef issue():\n    return User.query.first()\n`;
    expect(only(await scanOne(pathBased), "PY-012")).toEqual([]);
  });
  it("ignores files that import neither flask nor fastapi", async () => {
    const code = '@app.route("/u")\ndef u():\n    return User.query.all()\n';
    expect(only(await scanOne(code), "PY-012")).toEqual([]);
  });
});
