# ThreatSense: Cyber Intelligence Tool

## Overview
This web application functions by providing continuous data about potential threats actors, including indicators of compromise, giving security professionals an easily digestible, real-time look at known threats.

---
## Structure
API services offered by VirusTotal were integrated into this web application. Public Endpoints provided by the [VirusTotal APIs](https://developers.virustotal.com/v3.0/reference#public-vs-premium-api) are freely accessible to all registered users.Main features of the public API include:
* 4 requests per minute.
* Can be used in non-commercial products.

---
# App Components
ThreatSense provides users the following services:
1. Kaspersky's own real-time threatmap.
![Threatmap](https://drive.google.com/drive/u/1/folders/1R8eLy0uVBtvOoj-8otYCOlMsVO5eseSq)
2. identification of threats pertaining to -
    - Files, 
    - E-mails, 
    - IP Addressess and  
    - URLs
 3. Map showing origin of an IP Address
 ![Image of Yaktocat](https://octodex.github.com/images/yaktocat.png)
 
## Built With
* [Streamlit](https://www.streamlit.io/) - Open-source Python library that makes it easy to build beautiful custom web-apps for machine learning and data science.
* [VirusTotal](https://developers.virustotal.com/v3.0/reference#public-vs-premium-api) - VirusTotal's aggregates data from many different antivirus engines, website scanners, file and URL analysis tools.
* [PyDeck](https://deckgl.readthedocs.io/en/latest/installation.html) -  The pydeck library is a set of Python bindings for making spatial visualizations.
## Requirements
The requirements.txt file specified above contains all python dependencies. You can install them by running the command:

  `pip3 install -r requirements.txt`
  
