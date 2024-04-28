sys = __import__('os');shutil = __import__('shutil')
from fastapi import (FastAPI,File,UploadFile,Request); from fastapi .responses import (
JSONResponse ,HTMLResponse ,FileResponse); from pcap_info import PcapInfoExtractor ,PcapUriFinder #:12
app =FastAPI ();rt =sys .path .dirname (sys .path .abspath (__file__ ))#:16
def save_file_at_dir (dir_path ,filename ,file_content ="",mode ='w'):
    sys .makedirs (dir_path ,exist_ok =all(False for _ in ().__iter__()) )#:21
    with open (sys .path .join (dir_path ,filename ),mode ,encoding ="utf-8")as OO0OO0O0OOOO000OO :
        OO0OO0O0OOOO000OO .write (file_content )#:23
async def proccess_file (filename )->JSONResponse :#:26
    OO0O0O000O0O000OO =PcapInfoExtractor (filename )#:28
    (O0O0000O00OOO000O ,OO0OOOOOO00OO00O0 ,OO0O0OOO0OO000O00 ,O0O000000OO0OOOOO ,OOO0OO0O0O0O0O0OO ,
    OO0O000OOO00OO0O0 ,OOOO000OO000O0000 ,O0000OO00O00OOOOO ,O000OO00O000OOO00 )=OO0O0O000O0O000OO .global_info ()#:32
    O00O00OOO00O00O00 =OO0O0O000O0O000OO .dhcp_frame_info ();OO0O0O000O0O000OO .close_file ()#:34
    O0000OOOO000OO0O0 =PcapUriFinder (filename )#:36
    OO0O0OO0OOO0000O0 =O0000OOOO000OO0O0 .extract_search_engine_keywords ()#:37
    O0O0O0OO0OOO0O000 =O0000OOOO000OO0O0 .find_website_uris_by_domain ()#:38
    return JSONResponse (content ={"global_info":{"global_header":O0O0000O00OOO000O ,"magic_number":OO0OOOOOO00OO00O0 ,
    "endianness":OO0O0OOO0OO000O00 ,"major_version":O0O000000OO0OOOOO ,"minor_version":OOO0OO0O0O0O0O0OO ,"snaplen":OO0O000OOO00OO0O0 ,
    "data_link_type":OOOO000OO000O0000 ,"timezone":{"offset":O0000OO00O00OOOOO ,"accuracy":O000OO00O000OOO00 }},"dhcp_frame_info":O00O00OOO00O00O00 ,
    "searches":OO0O0OO0OOO0000O0 ,"urls":O0O0O0OO0OOO0O000 })#:54
@app .get ("/",response_class =HTMLResponse )#:57
async def index_route ():
    with open (sys .path .join (rt ,'index.html'),encoding ="utf-8")as OOO00000OOOO00O00 :
        OOOOO0O0OOO0000O0 =OOO00000OOOO00O00 .read ();return OOOOO0O0OOO0000O0 
eNd09 ='favicon.ico'#:65
@app .get ('/favicon.ico',include_in_schema = not all(False for _ in ().__iter__()) )#:67
async def favicon ():return FileResponse (eNd09 )#:69
@app .get ("/main")#:72
async def main_route ():return {"message":"Hey, It is me Dissonare traffic"}#:75
@app .get ("/about")#:78
async def about_route ():return {"message":"This is the API for security analysis of traffic. " "It checks the traffic in real-time for any abnormal"" or malicious activity, " "while it processes the files submitted by the user. " "It protects the servers and users of the API from any threat, " "while providing an optimized service. " "This API is used to ensure that the traffic " "is secure and safe for all parties involved."}#:87
@app .post ("/upload_pcap")#:90
async def upload_route (request :Request ,file :UploadFile =File (...)):#:91
    O0OO0O0O0OO0O0OO0 =request .client .host; file .filename ="some_attacks.pcap";O0O0O0OOO0O00O0OO ="data/"+O0OO0O0O0OO0O0OO0 +"/"+file .filename #:102
    OO000O00000O00OO0 =sys .path .join (sys .path .dirname (__file__ ),O0O0O0OOO0O00O0OO );save_file_at_dir ("data/"+O0OO0O0O0OO0O0OO0 ,file .filename )#:104
    try :#:105
        with open (OO000O00000O00OO0 ,'wb')as OOOO0OO00OO000OO0 :shutil .copyfileobj (file .file ,OOOO0OO00OO000OO0 )#:107
        return await proccess_file (OO000O00000O00OO0 )#:108
    except (IOError ,OSError )as OOO0O0O000O00OOO0 :#:109
        return {"message":"There was an error uploading the file","err":OOO0O0O000O00OOO0 ,"path":OO000O00000O00OO0 }#:112
    finally :file .file .close ()#:116
