"""
main api script saves the file and collects information about it
create by yarburart
"""
import os
import math
import shutil

from fastapi import (
    FastAPI, File,
    UploadFile, Request)
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.exceptions import HTTPException

from pcap_info import PcapInfoExtractor, PcapUriFinder


app = FastAPI()
root = os.path.dirname(os.path.abspath(__file__))
high_entropy_clients = {}

def save_file_at_dir(dir_path, filename, file_content="", mode='w'):
    """a little crutch of a path"""
    os.makedirs(dir_path, exist_ok=True)
    with open(os.path.join(dir_path, filename), mode, encoding="utf-8") as f:
        f.write(file_content)

def calculate_entropy(data: str) -> float:
    """calc Shannon entropy of data"""
    if not data:
        return 0.0

    frequency = {}
    length = len(data)

    for char in data: # calculate frequency of each character
        frequency[char] = frequency.get(char, 0) + 1

    return -sum((count / length) * math.log2(count / length) for count in frequency.values())

async def proccess_file(filename, client_ip: str, user_agent: str) -> JSONResponse:
    """Analyzes the pcap file and collects the result."""
    pcap_info = PcapInfoExtractor(filename)
    global_info = pcap_info.global_info()
    frame_tpl = pcap_info.dhcp_frame_info()
    pcap_info.close_file()

    data_to_analyze = ''.join(map(str, global_info)) + str(frame_tpl) # pcap info to string
    entropy = calculate_entropy(data_to_analyze)
    print(f"INFO: Entropy: {entropy} ")

    # check for high entropy and store client info if necessary
    if (client_ip, user_agent) in high_entropy_clients or not (4.2 <= entropy <= 6.0):
        high_entropy_clients[(client_ip, user_agent)] = True
        print(f"INFO: High entropy: {client_ip} {user_agent} {entropy} ") 
        raise HTTPException(status_code=403, detail="This might not be a valid pcap file.")

    # Proceed with the analysis if the entropy is acceptable
    pcap_finder = PcapUriFinder(filename)
    return JSONResponse(content={
        "global_info": {
            "global_header": global_info[0],
            "magic_number": global_info[1],
            "endianness": global_info[2],
            "major_version": global_info[3],
            "minor_version": global_info[4],
            "snaplen": global_info[5],
            "data_link_type": global_info[6],
            "timezone": {
                "offset": global_info[7],
                "accuracy": global_info[8]
            }
        },
        "dhcp_frame_info": frame_tpl,
        "searches": pcap_finder.extract_search_engine_keywords(),
        "urls": pcap_finder.find_website_uris_by_domain()
    })

@app.get("/", response_class=HTMLResponse)
async def index_route():
    """ returns a small file with all the gui you need """
    with open(os.path.join(root, 'index.html'), encoding="utf-8") as fh:
        data = fh.read()
    return data


favicon_path = 'favicon.ico'

@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    return FileResponse(favicon_path)


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
        return await proccess_file(path, request.client.host, request.headers.get('User-Agent'))
    except (IOError, OSError) as io_e:
        return {"message": "There was an error uploading the file",
                "err": io_e,  # debug, rewrite it for prod
                "path": path}
    finally:
        file.file.close()
