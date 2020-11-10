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

## Development Tracking
##### Priority
1. [ ] Documentation 
2. [ ] Bulk import of extension
3. [ ] Commenting feautre
4. [ ] Detection tagging and Yara
5. [ ] Reputation system
6. [ ] Related Extensions 
7. [ ] Update User Info
##### Dynamic analysis
- [ ] Whitelist filtering
- [ ] More details about request (size, ip, what else?)
- [ ] Proxy only extension network request
##### Static
- [ ] Beautify for other file formats (html,css,json,xml) 
##### Front End
- [ ] Real-time verbose frontend logging for scans
#### Dev Ops 
- [ ] Documentation
- [ ] CI Testing
- [ ] Docker Image
##### Detection 
- [ ] Yara scanning
- [ ] Rule storage and editing 
- [ ] Retrohunting   
- [ ] Tags
##### Backlog 
- [ ] Dynamic scans sort by time in report view 
##### Feature Ideas
- [ ] Graph explore view 
- [ ] Browser capture gif 

##### Completed
- [x] JS Beautify for file viewer 
- [x] Improve source view ui 
- [x] Deploy alpha
- [x] Service side profile & settings feature
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
