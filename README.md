# Dissonare traffic /

<img align="left" src="https://images.unsplash.com/photo-1567633090480-f19f2f67c088?q=80&w=1974&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D" width="33%" />

A utility to analyze traffic from a pcap file.

The architectural solutions here are focused on minimalism and a bit of laziness.

It's actually just an api skin on fastapi for the github.com/ftaxats/Pcap-Analyser repository. 

It's more interesting to use this as a training stand, as there are so many vulnerabilities there.
Obfuscated version on branch obf, it's more fun to hack.

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

On linux, you may need to use `python3 -m poetry` replacing `poetry`. Then you don't need to enter the `poetry shell`.

## or running in a Docker Container

Clone the repository:
```
git clone https://github.com/YarBurArt/Dissonare_traffic.git
```
```
cd Dissonare_traffic
```

Build and run the Docker image:
```
docker build -t dissonare_traffic .
```
```
docker run -p 8080:8080 dissonare_traffic
```

The application will now be available at `http://localhost:8080` or just the way you configure docker and linux virtual networks. 
Docker Isolation adds a new level of complexity and fun of exploitation through the escape step, especially this is my first project with a mini web app running on docker.  


On android in termux the poetry installation needs to be googled manually.

<!--  Hint: user input goes into the output, even with files of a different file type. Try to write an exploit on this. -->
