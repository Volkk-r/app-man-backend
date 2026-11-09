import json, os, socket, subprocess, sys, tempfile, time, unittest, urllib.request, urllib.error
from pathlib import Path

class API(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(); s=socket.socket(); s.bind(('127.0.0.1',0)); cls.port=s.getsockname()[1]; s.close()
        cls.base=f'http://127.0.0.1:{cls.port}'; env={**os.environ,'PORT':str(cls.port),'DATA_DIR':cls.tmp.name}
        cls.proc=subprocess.Popen([sys.executable,str(Path(__file__).with_name('app.py'))],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try: urllib.request.urlopen(cls.base+'/openapi.json'); break
            except OSError: time.sleep(.05)
        else: raise RuntimeError('Сервер не запустился')
    @classmethod
    def tearDownClass(cls): cls.proc.terminate(); cls.proc.wait(); cls.tmp.cleanup()
    def request(self,method,path,data=None,token=None,content_type='application/json'):
        headers={}
        if token: headers['Authorization']='Bearer '+token
        if data is not None:
            headers['Content-Type']=content_type
            if isinstance(data,dict): data=json.dumps(data).encode()
        req=urllib.request.Request(self.base+path,data=data,headers=headers,method=method)
        try: r=urllib.request.urlopen(req)
        except urllib.error.HTTPError as e: r=e
        with r:
            raw=r.read(); return r.status, json.loads(raw) if raw and r.headers.get_content_type()=='application/json' else raw
    def test_workflow(self):
        status,a=self.request('POST','/auth/register',{'name':'Anna','email':'anna@example.com','password':'password123'}); self.assertEqual(status,201); t=a['token']
        _,b=self.request('POST','/auth/register',{'name':'Other','email':'other@example.com','password':'password123'}); other=b['token']
        self.assertEqual(self.request('GET','/apartments/my')[0],401)
        status,a=self.request('POST','/apartments',{},t); self.assertEqual(status,201); aid=a['id']; path=f'/apartments/{aid}'
        self.assertEqual(self.request('GET',path,token=other)[0],403)
        self.assertEqual(self.request('PATCH',path,{'ownerId':2},t)[0],400)
        status,err=self.request('PATCH',path+'/status',{'status':'published'},t); self.assertEqual(status,400); self.assertIn('images',err['errors'])
        fields={'title':'Квартира','description':'Описание','city':'Ярославль','address':'Адрес','pricePerNight':3000,'maxGuests':2,'rooms':1,'beds':1,'bathrooms':1,'area':30,'floor':2,'rules':{'petsAllowed':True}}
        status,a=self.request('PATCH',path,fields,t); self.assertEqual(status,200); self.assertTrue(a['rules']['petsAllowed']); self.assertFalse(a['rules']['smokingAllowed'])
        boundary='testboundary'; png=b'\x89PNG\r\n\x1a\n' + b'test'
        body=b'--'+boundary.encode()+b'\r\nContent-Disposition: form-data; name="images"; filename="test.png"\r\nContent-Type: image/png\r\n\r\n'+png+b'\r\n--'+boundary.encode()+b'--\r\n'
        status,images=self.request('POST',path+'/images',body,t,'multipart/form-data; boundary='+boundary); self.assertEqual(status,201); self.assertTrue(images[0]['isCover'])
        self.assertEqual(self.request('PATCH',path+'/status',{'status':'published'},t)[0],200)
        self.assertEqual(self.request('GET',path)[0],200)
        self.assertEqual(self.request('PATCH',path+'/status',{'status':'archived'},t)[0],200)
        self.assertEqual(self.request('GET',path)[0],403)
        self.assertEqual(self.request('DELETE',path,token=other)[0],403)
        self.assertEqual(self.request('DELETE',path,token=t)[0],204)
        self.assertEqual(self.request('GET',images[0]['url'])[0],404)

if __name__=='__main__': unittest.main()
