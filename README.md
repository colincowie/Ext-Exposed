<p align="center">
  <img alt="Ext Exposed" src="https://github.com/colincowie/Ext-Exposed/raw/master/static/logo.png" height="140" />
  <br>
  <b>Ext Exposed</b>
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

## Development Tracking
##### Priority
1. [ ] Service side profile & settings feature
2. [ ] Platform security review (HTTPs and improve hashing algo)
3. [ ] Deploy alpha!
4. [ ] Documentation 
5. [ ] Bulk import of extension
6. [ ] Commenting feautre
7. [ ] Yara
8. [ ] Related Extensions 
##### Dynamic
- [ ] Proxy only extension network request?
- [ ] More details about request
- [ ] Whitelist filtering
##### Static
- [ ] JS Beautify for file viewer 
##### Front End
- [ ] Improve source view ui 
- [ ] Verbose frontend logging in real-time
#### Dev Ops 
- [ ] Documentation
- [ ] CI Testing
- [ ] Docker Image
##### Yara
- [ ] Yara scanning
- [ ] Rule storage
- [ ] Search output
- [ ] Web UI
- [ ] Tags?
##### Backlog 
- [ ] Improve scan sort 
##### Feature Ideas
- [ ] Graph explore view 
- [ ] Reputation system
- [ ] Browser capture gif 

##### Completed
- [x] Display and record extension full  name
- [x] Export to csv feautre 
- [x] Run chrome headless with virtual display
- [x] Source file viewing
- [x] Finish scan in progress / loading view
- [x] Scan log history in elasticsearch
- [x] Queue information
- [x] handle no redis errors
- [x] reporting page
- [x] Extension Submitting
- [x] Search Autodetect or two tabs
- [x] Stats page information populating
- [x] Download count
- [x] Elasticsearch uploading
- [x] Script integration
- [x] Javascript URLs
- [x] Permissions
- [x] Options
- [x] validate duplicate scanning
- [x] Elasticsearch uploading
- [x] Script integration
- [x] Run extension with proxy
- [x] Record extension network communications

</div>
