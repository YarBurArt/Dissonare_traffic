"""
main api script saves the file and collects information about it
create by yarburart
"""
import os
import shutil

from fastapi import (
    FastAPI, File,
    UploadFile, Request)
from fastapi.responses import JSONResponse, HTMLResponse

from pcap_info import PcapInfoExtractor, PcapUriFinder


app = FastAPI()
root = os.path.dirname(os.path.abspath(__file__))


def save_file_at_dir(dir_path, filename, file_content="", mode='w'):
    """a little crutch of a path"""
    os.makedirs(dir_path, exist_ok=True)
    with open(os.path.join(dir_path, filename), mode, encoding="utf-8") as f:
        f.write(file_content)


async def proccess_file(filename) -> JSONResponse:
    """using the pcap_info tool, analyzes the file and collects the result"""
    pcap_info = PcapInfoExtractor(filename)
    (global_header, magic_number,
     endianness, major_version, minor_version,
     snaplen, data_link_type,
     timezone_offset, timestamp_accuracy) = pcap_info.global_info()
    frame_tpl = pcap_info.dhcp_frame_info()
    pcap_info.close_file()

    pcap_finder = PcapUriFinder(filename)
    searches = pcap_finder.extract_search_engine_keywords()
    urls = pcap_finder.find_website_uris_by_domain()

    return JSONResponse(content={"global_info": {
                "global_header": global_header,
                "magic_number": magic_number,
                "endianness": endianness,
                "major_version": major_version,
                "minor_version": minor_version,
                "snaplen": snaplen,
                "data_link_type": data_link_type,
                "timezone": {
                    "offset": timezone_offset,
                    "accuracy": timestamp_accuracy}},
            "dhcp_frame_info": frame_tpl,
            "searches": searches,
            "urls": urls
            })


@app.get("/", response_class=HTMLResponse)
async def index_route():
    """ returns a small file with all the gui you need """
    with open(os.path.join(root, 'index.html'), encoding="utf-8") as fh:
        data = fh.read()
    return data


@app.get("/main")
async def main_route():
    """ just for echo test api """
    return {"message": "Hey, It is me Dissonare traffic"}


@app.get("/about")
async def about_route():
    """ basic information about the api and output, while here is a stub """
    return {"message": "This is the API for security analysis of traffic. "
                       "It checks the traffic in real-time for any abnormal or malicious activity, "
                       "while it processes the files submitted by the user. "
                       "It protects the servers and users of the API from any threat, "
                       "while providing an optimized service. "
                       "This API is used to ensure that the traffic "
                       "is secure and safe for all parties involved."}


@app.post("/upload_pcap")
async def upload_route(request: Request, file: UploadFile = File(...)):
    """
    Routes to the main load, returns the result of the analysis itself
    :param request: classic request parameters
    :param file: file, loaded in the stream
    :return: json with basic pcap parameters and security version
    """
    # user has only one analyze in one browser session + ip, so that's why there are no collisions
    client_ip = request.client.host
    file.filename = "some_attacks.pcap"

    rel_path = "data\\" + client_ip + "\\" + file.filename
    path = os.path.join(os.path.dirname(__file__), rel_path)
    save_file_at_dir("data/" + client_ip, file.filename)
    try:
        with open(path, 'wb') as f:
            shutil.copyfileobj(file.file, f)
        return await proccess_file(path)
    except (IOError, OSError) as io_e:
        return {"message": "There was an error uploading the file",
                "err": io_e,  # debug, rewrite it for prod
                "path": path}
    finally:
        file.file.close()
