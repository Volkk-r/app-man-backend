import base64, hashlib, hmac, json, os, re, secrets, sqlite3, time, uuid
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get('DATA_DIR', ROOT / 'data')).resolve()
UPLOADS = DATA / 'uploads'
UPLOADS.mkdir(parents=True, exist_ok=True)
DB = DATA / 'apartments.sqlite3'
SECRET_FILE = DATA / 'jwt-secret'
if not SECRET_FILE.exists():
    SECRET_FILE.write_text(secrets.token_hex(32))
SECRET = os.environ.get('JWT_SECRET', SECRET_FILE.read_text().strip()).encode()
PORT = int(os.environ.get('PORT', '3000'))
MAX_FILE = 5 * 1024 * 1024
MAX_BODY = 10 * MAX_FILE + 1024 * 1024
FIELDS = {'title': str, 'description': str, 'city': str, 'address': str, 'pricePerNight': float, 'maxGuests': int, 'rooms': int, 'beds': int, 'bathrooms': int, 'area': float, 'floor': int, 'amenities': list, 'rules': dict}
RULES = {'checkIn': str, 'checkOut': str, 'smokingAllowed': bool, 'petsAllowed': bool, 'childrenAllowed': bool}
DEFAULTS = {'title':'', 'description':'', 'city':'', 'address':'', 'pricePerNight':None, 'maxGuests':None, 'rooms':None, 'beds':None, 'bathrooms':None, 'area':None, 'floor':None, 'amenities':[], 'rules':{'checkIn':'', 'checkOut':'', 'smokingAllowed':False, 'petsAllowed':False, 'childrenAllowed':False}}

def db():
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys = ON')
    return c
with db() as c:
    c.executescript('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS apartments (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), data TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS images (id INTEGER PRIMARY KEY, apartment_id INTEGER NOT NULL REFERENCES apartments(id) ON DELETE CASCADE, filename TEXT NOT NULL, is_cover INTEGER NOT NULL DEFAULT 0);''')

def now(): return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def enc(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def dec(s): return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
def token(uid):
    a = enc(json.dumps({'alg':'HS256','typ':'JWT'}, separators=(',',':')).encode())
    b = enc(json.dumps({'sub':str(uid),'exp':int(time.time())+7*86400}, separators=(',',':')).encode())
    return a+'.'+b+'.'+enc(hmac.new(SECRET, (a+'.'+b).encode(), hashlib.sha256).digest())
def verify(t):
    try:
        a,b,s = t.split('.')
        if not hmac.compare_digest(dec(s), hmac.new(SECRET,(a+'.'+b).encode(),hashlib.sha256).digest()): return None
        header, payload = json.loads(dec(a)), json.loads(dec(b))
        if header.get('alg') != 'HS256' or payload['exp'] <= time.time(): return None
        return int(payload['sub'])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError): return None

def password_hash(p, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + ':' + hashlib.pbkdf2_hmac('sha256', p.encode(), bytes.fromhex(salt), 200000).hex()
def image_obj(row): return {'id':row['id'], 'url':'/uploads/'+row['filename'], 'isCover':bool(row['is_cover'])}
def apartment(c, row):
    obj = {'id':row['id'], 'ownerId':row['owner_id'], **json.loads(row['data']), 'images':[image_obj(i) for i in c.execute('SELECT * FROM images WHERE apartment_id=? ORDER BY id',(row['id'],))], 'status':row['status'], 'createdAt':row['created_at'], 'updatedAt':row['updated_at']}
    return obj

def validate(data):
    errors = {}
    if not isinstance(data, dict): return {'body':'Ожидается JSON-объект'}
    for k,v in data.items():
        if k not in FIELDS:
            errors[k] = 'Поле нельзя изменить'; continue
        t = FIELDS[k]
        if v is None and t in (int,float): continue
        if t in (int,float):
            if isinstance(v,bool) or not isinstance(v,(int,float)) or (t is int and not isinstance(v,int)) or v < 0 or not (v < 1e12): errors[k] = 'Укажите корректное неотрицательное число' + (' без дробной части' if t is int else '')
        elif not isinstance(v,t): errors[k] = 'Некорректный тип значения'
        elif k == 'amenities' and any(not isinstance(x,str) for x in v): errors[k] = 'Список удобств должен содержать строки'
        elif k == 'rules':
            for rk,rv in v.items():
                if rk not in RULES or type(rv) is not RULES[rk]: errors['rules.'+rk] = 'Неизвестное правило или некорректный тип'
                elif rk in ('checkIn','checkOut') and rv and not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d',rv): errors['rules.'+rk] = 'Укажите время в формате ЧЧ:ММ'
    return errors

def publication_errors(a):
    e = {}
    for k in ('title','description','city','address'):
        if not a[k].strip(): e[k] = 'Заполните поле'
    for k in ('pricePerNight','maxGuests','rooms','beds','area'):
        if a[k] is None or a[k] <= 0: e[k] = 'Укажите значение больше нуля'
    for k in ('bathrooms','floor'):
        if a[k] is None: e[k] = 'Укажите значение'
    if not a['images']: e['images'] = 'Добавьте хотя бы одну фотографию'
    return e

def signature(content):
    if content.startswith(b'\xff\xd8\xff'): return 'jpg'
    if content.startswith(b'\x89PNG\r\n\x1a\n'): return 'png'
    if content[:4] == b'RIFF' and content[8:12] == b'WEBP': return 'webp'
    return None

class Handler(BaseHTTPRequestHandler):
    def send(self, code, obj=None, headers=None):
        payload = b'' if obj is None else json.dumps(obj, ensure_ascii=False, allow_nan=False).encode()
        self.send_response(code)
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Headers','Content-Type, Authorization')
        self.send_header('Access-Control-Allow-Methods','GET, POST, PATCH, DELETE, OPTIONS')
        if obj is not None: self.send_header('Content-Type','application/json; charset=utf-8')
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.send_header('Content-Length',str(len(payload))); self.end_headers()
        if payload: self.wfile.write(payload)
    def fail(self, code, msg, errors=None):
        self.send(code, {'message':msg, **({'errors':errors} if errors else {})}); return None
    def body(self):
        try:
            n = int(self.headers.get('Content-Length','0'))
            if n < 0 or n > MAX_BODY: raise ValueError('Размер запроса превышает допустимый')
            return self.rfile.read(n)
        except ValueError as e: self.fail(400,str(e)); raise Handled()
    def json_body(self):
        try:
            if 'application/json' not in self.headers.get('Content-Type',''): raise ValueError()
            return json.loads(self.body(), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeDecodeError): self.fail(400,'Передайте корректный JSON'); raise Handled()
    def user(self,c, required=True):
        auth = self.headers.get('Authorization','')
        uid = verify(auth[7:]) if auth.startswith('Bearer ') else None
        u = c.execute('SELECT id, name, email FROM users WHERE id=?',(uid,)).fetchone() if uid else None
        if not u and (required or auth): self.fail(401,'Необходима авторизация'); raise Handled()
        return u
    def owned(self,c,aid,u):
        row = c.execute('SELECT * FROM apartments WHERE id=?',(aid,)).fetchone()
        if not row: self.fail(404,'Квартира не найдена'); raise Handled()
        if row['owner_id'] != u['id']: self.fail(403,'Нет доступа к этой квартире'); raise Handled()
        return row
    def do_OPTIONS(self): self.send(204)
    def do_GET(self): self.handle_request('GET')
    def do_POST(self): self.handle_request('POST')
    def do_PATCH(self): self.handle_request('PATCH')
    def do_DELETE(self): self.handle_request('DELETE')
    def handle_request(self, method):
        try: self.route(method)
        except Handled: pass
        except (BrokenPipeError, ConnectionResetError): pass
        except Exception as e:
            print('Server error:', repr(e), flush=True)
            self.fail(500,'Внутренняя ошибка сервера')
    def route(self, method):
        path = urlparse(self.path).path.rstrip('/') or '/'
        if method == 'GET' and path == '/openapi.json': return self.send(200, openapi())
        if method == 'GET' and path in ('/docs','/'):
            html = b'''<!doctype html><html><head><meta charset="utf-8"><title>Apartment Management API</title><link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"></head><body><div id="swagger-ui"></div><script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui',persistAuthorization:true})</script></body></html>'''
            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(html))); self.end_headers(); self.wfile.write(html); return
        if method == 'GET' and path.startswith('/uploads/'):
            filename = path.removeprefix('/uploads/')
            if not re.fullmatch(r'[a-f0-9]{32}\.(jpg|png|webp)',filename): return self.fail(404,'Файл не найден')
            with db() as c:
                row=c.execute('SELECT a.status FROM images i JOIN apartments a ON a.id=i.apartment_id WHERE i.filename=?',(filename,)).fetchone()
                if not row: return self.fail(404,'Файл не найден')
            # Image URLs are public, like static files; unguessable filenames do not expose apartment data.
            p=UPLOADS/filename
            if not p.exists(): return self.fail(404,'Файл не найден')
            content=p.read_bytes(); mime={'jpg':'image/jpeg','png':'image/png','webp':'image/webp'}[p.suffix[1:]]
            self.send_response(200); self.send_header('Content-Type',mime); self.send_header('Content-Length',str(len(content))); self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(content); return
        with db() as c:
            if path in ('/auth/register','/auth/login') and method == 'POST':
                d=self.json_body()
                if not isinstance(d,dict): return self.fail(400,'Ошибка валидации',{'body':'Ожидается объект'})
                email=d.get('email'); pwd=d.get('password'); name=d.get('name')
                errors={}
                if not isinstance(email,str) or len(email)>254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email): errors['email']='Укажите корректный email'
                if not isinstance(pwd,str) or not 8 <= len(pwd) <= 128: errors['password']='Пароль должен содержать от 8 до 128 символов'
                if path.endswith('register') and (not isinstance(name,str) or not name.strip() or len(name)>100): errors['name']='Укажите имя до 100 символов'
                if errors: return self.fail(400,'Ошибка валидации',errors)
                email=email.strip().lower()
                if path.endswith('register'):
                    try: uid=c.execute('INSERT INTO users(name,email,password) VALUES(?,?,?)',(name.strip(),email,password_hash(pwd))).lastrowid; c.commit()
                    except sqlite3.IntegrityError: return self.fail(400,'Ошибка валидации',{'email':'Пользователь с таким email уже существует'})
                    u={'id':uid,'name':name.strip(),'email':email}; return self.send(201,{'user':u,'token':token(uid)})
                row=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
                if not row or not hmac.compare_digest(row['password'],password_hash(pwd,row['password'].split(':')[0])): return self.fail(401,'Неверный email или пароль')
                return self.send(200,{'user':{'id':row['id'],'name':row['name'],'email':row['email']},'token':token(row['id'])})
            if path == '/auth/me' and method == 'GET': return self.send(200,dict(self.user(c)))
            if path == '/apartments/my' and method == 'GET':
                u=self.user(c); rows=c.execute('SELECT * FROM apartments WHERE owner_id=? ORDER BY updated_at DESC,id DESC',(u['id'],)).fetchall(); result=[]
                for r in rows:
                    a=apartment(c,r); cover=next((i for i in a['images'] if i['isCover']),None)
                    result.append({k:a[k] for k in ('id','title','city','address','pricePerNight','status','updatedAt')} | {'coverImage':cover})
                return self.send(200,result)
            if path == '/apartments' and method == 'POST':
                u=self.user(c); d=self.json_body(); errors=validate(d)
                if errors: return self.fail(400,'Ошибка валидации',errors)
                data={**DEFAULTS, **d}; data['rules']={**DEFAULTS['rules'],**d.get('rules',{})}; timestamp=now()
                aid=c.execute('INSERT INTO apartments(owner_id,data,status,created_at,updated_at) VALUES(?,?,?,?,?)',(u['id'],json.dumps(data,ensure_ascii=False),'draft',timestamp,timestamp)).lastrowid; c.commit()
                return self.send(201,apartment(c,c.execute('SELECT * FROM apartments WHERE id=?',(aid,)).fetchone()))
            match=re.fullmatch(r'/apartments/(\d+)(?:/(status|images)(?:/(\d+)(?:/(cover))?)?)?',path)
            if not match: return self.fail(404,'Маршрут не найден')
            aid=int(match[1]); section=match[2]; iid=int(match[3]) if match[3] else None; cover=match[4]
            if not section and method == 'GET':
                u=self.user(c,False); row=c.execute('SELECT * FROM apartments WHERE id=?',(aid,)).fetchone()
                if not row: return self.fail(404,'Квартира не найдена')
                if row['status'] != 'published' and (not u or u['id'] != row['owner_id']): return self.fail(403,'Нет доступа к этой квартире')
                return self.send(200,apartment(c,row))
            u=self.user(c); row=self.owned(c,aid,u)
            if not section and method == 'PATCH':
                d=self.json_body(); errors=validate(d)
                if errors: return self.fail(400,'Ошибка валидации',errors)
                data=json.loads(row['data'])
                if 'rules' in d: d['rules']={**data['rules'],**d['rules']}
                data.update(d); c.execute('UPDATE apartments SET data=?, updated_at=? WHERE id=?',(json.dumps(data,ensure_ascii=False),now(),aid)); c.commit()
                return self.send(200,apartment(c,c.execute('SELECT * FROM apartments WHERE id=?',(aid,)).fetchone()))
            if not section and method == 'DELETE':
                files=[x['filename'] for x in c.execute('SELECT filename FROM images WHERE apartment_id=?',(aid,))]; c.execute('DELETE FROM apartments WHERE id=?',(aid,)); c.commit()
                for f in files: (UPLOADS/f).unlink(missing_ok=True)
                return self.send(204)
            if section == 'status' and iid is None and method == 'PATCH':
                d=self.json_body()
                if not isinstance(d,dict) or set(d)!={'status'} or d['status'] not in ('draft','published','archived'): return self.fail(400,'Ошибка валидации',{'status':'Укажите допустимый статус'})
                status=d['status']
                if (row['status'],status) not in (('draft','published'),('published','archived'),('archived','published')): return self.fail(400,'Недопустимый переход статуса')
                if status == 'published':
                    errors=publication_errors(apartment(c,row))
                    if errors: return self.fail(400,'Ошибка валидации',errors)
                c.execute('UPDATE apartments SET status=?,updated_at=? WHERE id=?',(status,now(),aid)); c.commit()
                return self.send(200,apartment(c,c.execute('SELECT * FROM apartments WHERE id=?',(aid,)).fetchone()))
            if section == 'images' and iid is None and method == 'POST':
                ctype=self.headers.get('Content-Type','')
                if not ctype.lower().startswith('multipart/form-data;') or 'boundary=' not in ctype: return self.fail(400,'Ожидается multipart/form-data')
                raw=self.body(); msg=BytesParser(policy=default).parsebytes(('Content-Type: '+ctype+'\r\nMIME-Version: 1.0\r\n\r\n').encode()+raw)
                if not msg.is_multipart(): return self.fail(400,'Некорректный multipart-запрос')
                parts=list(msg.iter_parts()); files=[]
                for p in parts:
                    if p.get_param('name',header='content-disposition') != 'images' or not p.get_filename(): return self.fail(400,'Используйте поле images для загрузки файлов')
                    content=p.get_payload(decode=True) or b''; ext=signature(content)
                    expected={'jpg':'image/jpeg','png':'image/png','webp':'image/webp'}
                    if not ext or p.get_content_type() != expected[ext]: return self.fail(400,'Допустимы только изображения JPEG, PNG и WebP')
                    if len(content)>MAX_FILE: return self.fail(400,'Размер каждого файла не должен превышать 5 МБ')
                    files.append((uuid.uuid4().hex+'.'+ext,content))
                if not files: return self.fail(400,'Добавьте фотографии')
                written=[]
                try:
                    c.execute('BEGIN IMMEDIATE')
                    count=c.execute('SELECT COUNT(*) FROM images WHERE apartment_id=?',(aid,)).fetchone()[0]
                    if count+len(files)>10: c.rollback(); return self.fail(400,'Можно загрузить не более 10 фотографий')
                    added=[]
                    for idx,(filename,content) in enumerate(files):
                        (UPLOADS/filename).write_bytes(content); written.append(filename)
                        image_id=c.execute('INSERT INTO images(apartment_id,filename,is_cover) VALUES(?,?,?)',(aid,filename,int(count==0 and idx==0))).lastrowid
                        added.append(image_obj(c.execute('SELECT * FROM images WHERE id=?',(image_id,)).fetchone()))
                    c.execute('UPDATE apartments SET updated_at=? WHERE id=?',(now(),aid)); c.commit()
                except Exception:
                    c.rollback()
                    for f in written: (UPLOADS/f).unlink(missing_ok=True)
                    raise
                return self.send(201,added)
            if section == 'images' and iid is not None:
                img=c.execute('SELECT * FROM images WHERE id=? AND apartment_id=?',(iid,aid)).fetchone()
                if not img: return self.fail(404,'Фотография не найдена')
                if cover and method == 'PATCH':
                    c.execute('UPDATE images SET is_cover=0 WHERE apartment_id=?',(aid,)); c.execute('UPDATE images SET is_cover=1 WHERE id=?',(iid,)); c.execute('UPDATE apartments SET updated_at=? WHERE id=?',(now(),aid)); c.commit()
                    return self.send(200,apartment(c,c.execute('SELECT * FROM apartments WHERE id=?',(aid,)).fetchone()))
                if not cover and method == 'DELETE':
                    c.execute('DELETE FROM images WHERE id=?',(iid,))
                    if img['is_cover']: c.execute('UPDATE images SET is_cover=1 WHERE id=(SELECT id FROM images WHERE apartment_id=? ORDER BY id LIMIT 1)',(aid,))
                    c.execute('UPDATE apartments SET updated_at=? WHERE id=?',(now(),aid)); c.commit(); (UPLOADS/img['filename']).unlink(missing_ok=True)
                    return self.send(204)
            return self.fail(404,'Маршрут не найден')
class Handled(Exception): pass

def openapi():
    string={'type':'string'}; integer={'type':'integer','minimum':0,'nullable':True}; number={'type':'number','minimum':0,'nullable':True}
    rules={'type':'object','properties':{'checkIn':{'type':'string','example':'14:00'},'checkOut':{'type':'string','example':'12:00'},'smokingAllowed':{'type':'boolean'},'petsAllowed':{'type':'boolean'},'childrenAllowed':{'type':'boolean'}}}
    props={'title':string,'description':string,'city':string,'address':string,'pricePerNight':number,'maxGuests':integer,'rooms':integer,'beds':integer,'bathrooms':integer,'area':number,'floor':integer,'amenities':{'type':'array','items':string},'rules':rules}
    fields={'type':'object','properties':props,'additionalProperties':False}
    image={'type':'object','properties':{'id':{'type':'integer'},'url':string,'isCover':{'type':'boolean'}}}
    apt={'type':'object','properties':{'id':{'type':'integer'},'ownerId':{'type':'integer'},**props,'images':{'type':'array','items':image},'status':{'type':'string','enum':['draft','published','archived']},'createdAt':string,'updatedAt':string}}
    def response(desc,schema=None):
        r={'description':desc}
        if schema: r['content']={'application/json':{'schema':schema}}
        return r
    def op(summary, schema=None, result=None, code='200', auth=True, multipart=False):
        o={'summary':summary,'responses':{code:response('Успешно',result),'400':response('Ошибка валидации'),'401':response('Необходима авторизация'),'403':response('Доступ запрещён'),'404':response('Не найдено')}}
        if auth: o['security']=[{'bearerAuth':[]}]
        if schema: o['requestBody']={'required':True,'content':{('multipart/form-data' if multipart else 'application/json'):{'schema':schema}}}
        return o
    auth_result={'type':'object','properties':{'token':string,'user':{'type':'object','properties':{'id':{'type':'integer'},'name':string,'email':string}}}}
    cred={'type':'object','required':['email','password'],'properties':{'email':{'type':'string','format':'email'},'password':{'type':'string','format':'password','minLength':8}}}
    reg={'type':'object','required':['name','email','password'],'properties':{'name':string,**cred['properties']}}
    aid={'name':'apartmentId','in':'path','required':True,'schema':{'type':'integer'}}; iid={'name':'imageId','in':'path','required':True,'schema':{'type':'integer'}}
    paths={
      '/auth/register':{'post':op('Регистрация',reg,auth_result,'201',False)}, '/auth/login':{'post':op('Вход',cred,auth_result,auth=False)}, '/auth/me':{'get':op('Текущий пользователь',result=auth_result['properties']['user'])},
      '/apartments/my':{'get':op('Список своих квартир',result={'type':'array','items':{'type':'object','properties':{k:apt['properties'][k] for k in ('id','title','city','address','pricePerNight','status','updatedAt')} | {'coverImage':{**image,'nullable':True}}}})},
      '/apartments':{'post':op('Создать черновик',fields,apt,'201')},
      '/apartments/{apartmentId}':{'parameters':[aid],'get':op('Получить квартиру (для черновика нужен токен владельца)',result=apt,auth=False),'patch':op('Изменить квартиру',fields,apt),'delete':op('Удалить квартиру',code='204')},
      '/apartments/{apartmentId}/status':{'parameters':[aid],'patch':op('Изменить статус',{'type':'object','required':['status'],'properties':{'status':{'type':'string','enum':['published','archived']}}},apt)},
      '/apartments/{apartmentId}/images':{'parameters':[aid],'post':op('Загрузить фотографии',{'type':'object','required':['images'],'properties':{'images':{'type':'array','items':{'type':'string','format':'binary'}}}}, {'type':'array','items':image},'201',multipart=True)},
      '/apartments/{apartmentId}/images/{imageId}':{'parameters':[aid,iid],'delete':op('Удалить фотографию',code='204')},
      '/apartments/{apartmentId}/images/{imageId}/cover':{'parameters':[aid,iid],'patch':op('Выбрать главную фотографию',result=apt)} }
    return {'openapi':'3.0.3','info':{'title':'Apartment Management API','version':'1.0.0','description':'JWT: зарегистрируйтесь или войдите, скопируйте token и нажмите Authorize.'},'components':{'securitySchemes':{'bearerAuth':{'type':'http','scheme':'bearer','bearerFormat':'JWT'}}},'paths':paths}

if __name__ == '__main__':
    print(f'Apartment Management API: http://localhost:{PORT}/docs', flush=True)
    ThreadingHTTPServer(('127.0.0.1',PORT),Handler).serve_forever()
