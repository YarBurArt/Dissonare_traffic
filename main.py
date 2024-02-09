import os

from fastapi import (
    FastAPI, File, UploadFile,
    Request, Response)
import shutil

from pcap_info import PcapInfoExtractor, PcapUriFinder


app = FastAPI()
root = os.path.dirname(os.path.abspath(__file__))


def save_file_at_dir(dir_path, filename, file_content="", mode='w'):
    os.makedirs(dir_path, exist_ok=True)
    with open(os.path.join(dir_path, filename), mode) as f:
        f.write(file_content)


async def proccess_file(filename):
    pcap_info = PcapInfoExtractor(filename)
    (global_header, magic_number,
     endianness, major_version, minor_version,
     snaplen, data_link_type) = pcap_info.global_info()
    frame_tpl = pcap_info.dhcp_frame_info()
    pcap_info.close_file()

    pcap_finder = PcapUriFinder(filename)
    searches = pcap_finder.extract_search_engine_keywords()
    urls = pcap_finder.find_website_uris_by_domain()

    return {"global_info": {
                "global_header": global_header,
                "magic_number": magic_number,
                "endianness": endianness,
                "major_version": major_version,
                "minor_version": minor_version,
                "snaplen": snaplen,
                "data_link_type": data_link_type},
            "dhcp_frame_info": frame_tpl,
            "searches": searches,
            "urls": urls
            }


@app.get("/")
async def index_route():
    with open(os.path.join(root, 'index.html')) as fh:
        data = fh.read()
    return Response(content=data, media_type="text/html")


@app.get("/main")
async def main_route():
    return {"message": "Hey, It is me Dissonare traffic"}


@app.get("/about")
async def about_route():
    return {"message": "This is the API for security analysis of traffic. "
                       "It checks the traffic in real-time for any abnormal or malicious activity, "
                       "while it processes the files submitted by the user. "
                       "It protects the servers and users of the API from any threat, "
                       "while providing an optimized service. "
                       "This API is used to ensure that the traffic is secure and safe for all parties involved."}


@app.post("/upload_pcap")
async def upload_route(request: Request, file: UploadFile = File(...)):
    client_ip = request.client.host
    rel_path = "data\\" + client_ip + "\\" + file.filename
    path = os.path.join(os.path.dirname(__file__), rel_path)
    save_file_at_dir("data/" + client_ip, file.filename)  # FIXME
    try:
        with open(path, 'wb') as f:
            shutil.copyfileobj(file.file, f)
    except Exception as e:
        return {"message": "There was an error uploading the file",
                "err": e,
                "path": path}
    finally:
        file.file.close()

    try:
        return await proccess_file(path)
    except Exception:
        return {"message": "There was an error processing the file",
                "error": Exception}  # FIXME
