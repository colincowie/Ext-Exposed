<p align="center">
  <img alt="Ext Exposed" src="https://github.com/colincowie/CRX-Hunt/raw/master/static/logo.png" height="140" />
  <br>
  <b>Ext Exposed</b>
  <br>
  <i>A threat hunting platform for chrome extensions</i>
  <br>
  <img src="https://img.shields.io/github/last-commit/colincowie/CRX-Hunt"/> <img src="https://img.shields.io/github/repo-size/colincowie/CRX-Hunt"/>
</p>


## Features
#### Chrome Extension Static Analysis
- Javascript URLs
- Permissions
- Extension Metadata
#### Chrome Extension Dynamic Analysis
- Run extension with proxy
- Record extension network communications
#### Query Extension Information
- Search by extension, domain or IP address
- Elasticsearch database
#### Web UI
- Python Flask web interface

## Requirements
- Elasticsearch
- Python 3
- Webdriver

## Usage
#### Install

1. Create a new python virutal enviroment (option)
  - `python3 -m venv env`
  - `source env/bin/activate`

2. Install python requirements
  - `python3 -m pip install -r requirements.txt`

#### Elasticsearch setup
1. Pull docker
  - `docker pull docker.elastic.co/elasticsearch/elasticsearch:7.9.0`
2. Start a single docker node
  - `docker run -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" docker.elastic.co/elasticsearch/elasticsearch:7.9.0`
3. Create a index for CRX Hunt
  - `curl -X PUT "localhost:9200/crx?pretty"`

##### Static analysis (only urls currently)
1. `python3 ext_analyze.py`
2. Provide extension ID
<img src="https://github.com/colincowie/CRX-Hunt/raw/master/static/github/analyze_demo.png"/>

##### Dynamic analysis
1. `python3 ext_sandbox.py`
2. Provide extension ID
<img src="https://github.com/colincowie/CRX-Hunt/raw/master/static/github/dynamic_demo.png"/>

Saves URLs to `reports/extension_id/mitm_urls.txt`

Saves request and responses to `reports/extension_id/mitm_content.txt`

## Design
<img src="https://github.com/colincowie/CRX-Hunt/raw/master/diagram.png" height="500"/>

## Development Tracking
##### Priority
- [ ] improved extension reporting
- [ ] update requirements.txt
##### Dynamic
- [ ] Options
- [ ] Elasticsearch uploading
- [x] Script integration
- [x] Run extension with proxy
- [x] Record extension network communications
##### Static
- [x] Script integration
- [x] Javascript URLs
- [x] Permissions
- [x] Download count
- [x] Elasticsearch uploading
##### Front End
- [ ] Stats page buttons?
- [x] Extension Submitting
- [x] Search Autodetect or two tabs
- [x] Stats page information populating
##### Yara
- [ ] Search output
- [ ] Web UI
