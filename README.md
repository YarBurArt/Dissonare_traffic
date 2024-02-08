# Dissonare traffic /

<img align="left" src="https://images.unsplash.com/photo-1567633090480-f19f2f67c088?q=80&w=1974&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D" width="33%" />

A utility to analyze traffic from a pcap file.

It's actually just an api skin on fastapi for the github.com/ftaxats/Pcap-Analyser repository. 

It's more interesting to use this as a training stand, as there are so many vulnerabilities there.

To use this as a stand for practicing web security testing skills /

```
git clone https://github.com/YarBurArt/Dissonare_traffic.git
```
```
cd Dissonare_traffic
```
```
poetry install 
```
```
poetry shell 
```
```
poetry run uvicorn main:app --reload --port 8001
```
