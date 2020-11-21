<p align="center">
  <img alt="Ext Exposed" src="https://github.com/colincowie/Ext-Exposed/raw/master/static/logo.png" height="140" />
  <br>
  <b>Ext Exposed (in development)</b>
  <br>
  <i>A threat hunting platform for chrome extensions</i>
  <br>
    <img src="https://img.shields.io/badge/-Python%20Flask-orange"/>
  <img src="https://img.shields.io/github/last-commit/colincowie/Ext-Exposed"/> 
  <img src="https://img.shields.io/github/repo-size/colincowie/Ext-Exposed"/>

  
</p>

## Features
#### Static Analysis
- Javascript URLs
- Permissions
- Extension source code viewer 
- Yara rule scanning   
#### Dynamic Analysis
- Runs chrome extensions with a proxy 
- Records browser network request
- Runtime playbooks (coming soon)
#### Query Extension Information
- Search by extension name, id, permissions static or dynamic analysis urls
#### Web UI
- Web interface built in python flask
- Export data in csv format
- Share yara rules with other users  

## Requirements
- Python 3
- Elasticsearch
- Webdriver
- Redis Server (used for queuing analysis task)

## Usage
1. `python3 crx_hunt.py`
2. `vist 127.0.0.1:8080`

#### Install Dependencies 

1. Install python requirements
  - `python3 -m pip install -r requirements.txt`
  
#### Redis setup
1. run redis server
  - `redis-server`
2. run rq working in project directory
  - `rq worker`

#### Elasticsearch setup
1. Pull docker
  - `docker pull docker.elastic.co/elasticsearch/elasticsearch:7.9.0`
2. Start a docker instance for elasticsearch
  - `docker run -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" docker.elastic.co/elasticsearch/elasticsearch:7.9.0`


## Design
<img src="https://github.com/colincowie/CRX-Hunt/raw/master/diagram.png" height="500"/>
