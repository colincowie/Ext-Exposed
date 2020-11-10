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
#### Chrome Extension Static Analysis
- Javascript URLs
- Permissions
- Extension Source Code
- Extension Metadata
#### Chrome Extension Dynamic Analysis
- Record extension network communications 
#### Query Extension Information
- Search by extension, domain, permission and more 
- Elasticsearch database
#### Web UI
- Python Flask web interface

## Requirements
- Elasticsearch
- Python 3
- Webdriver

## Usage
`python3 crx_hunt.py`

#### Install

1. Install python requirements
  - `python3 -m pip install -r requirements.txt`

#### Elasticsearch setup
1. Pull docker
  - `docker pull docker.elastic.co/elasticsearch/elasticsearch:7.9.0`
2. Start a docker instance for elasticsearch
  - `docker run -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" docker.elastic.co/elasticsearch/elasticsearch:7.9.0`

#### Redis setup
1. run redis server
  - `redis-server`
2. run rq working in project directory
  - `rq worker`

## Design
<img src="https://github.com/colincowie/CRX-Hunt/raw/master/diagram.png" height="500"/>
