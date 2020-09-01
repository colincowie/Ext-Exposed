<p align="center">
  <img alt="CRX Hunt" src="https://github.com/colincowie/CRX-Hunt/raw/master/static/logo.png" height="140" />
  <br>
  <b>CRX Hunt</b>
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

## Usage
#### Install

1. Create a new python virutal enviroment (option) 
  - `python3 -m venv env`
  - `source env/bin/activate`

2. Install python requirements 
  - `python3 -m pip install -r requirements.txt`

##### Static analysis (only urls currently)
1. `python3 ext_analyze.py`
2. Provide extension ID
<img src="https://github.com/colincowie/CRX-Hunt/raw/master/static/github/analyze_demo.png"/>

##### Dynamic analysis (currently only logs to terminal)
1. `python3 ext_sandbox.py`
2. Provide extension ID
<img src="https://github.com/colincowie/CRX-Hunt/raw/master/static/github/dynamic_demo.png"/>

## Design
<img src="https://github.com/colincowie/CRX-Hunt/raw/master/diagram.png" height="500"/>

## Development Tracking 
##### Dynamic
- [x] Script intergration
- [x] Run extension with proxy
- [ ] Record extension network communications
- [ ] Elasticsearch uploading
##### Static
- [x] Script intergration
- [ ] Javascript URLs
- [ ] Permissions
- [ ] Extension Metadata
- [ ] Elasticsearch uploading
##### Front End
- [ ] Extension Submitting
- [ ] Search Autodetect or two tabs
- [ ] Stats page information populating 
