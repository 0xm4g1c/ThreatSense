import streamlit as st
import pandas as pd
import requests
import pydeck as pdk
import hashlib
import json
import re, validators
import plotly.graph_objects as go
import data_visualization as dv
import os
#import config
from requests.exceptions import ConnectionError
from contextlib import suppress
from ipdata import ipdata
from datetime import datetime, date

st.title("ThreatSense :computer:")

# config vars from Heroku dashboard
file_secret = os.getenv('file')
ip_secret = os.getenv('ip')
url_secret = os.getenv('url')


# sidebars
datavisual_choice = st.sidebar.radio("Navigate Pages",
("Threat Map", "File Scanner", "Scan Credentials"))

# welcome page
if datavisual_choice == "Threat Map":
    st.header("**Vulnerability Scanner for everyone**")
    st.write(" ### Find technical information about internet assets before **_HACKERS_** do")
    dv.threatmap()
    
# File Scanner
if datavisual_choice =="File Scanner":
    st.write("### Scan files for known threats")
    dv.svg_assets(image="Assets/my_files.svg")
    try:
        uploaded_file = st.file_uploader("Choose a file to scan..")    
        if uploaded_file is not None:
            # getting hash value of uploaded file
            bytes = uploaded_file.read()
            uploaded_file_hash = hashlib.md5(bytes).hexdigest()
            # add hash to endpoint
            file_endpoint = "https://www.virustotal.com/api/v3/files/" +  uploaded_file_hash
            file_headers = {'x-apikey': file_secret}
            file_response = requests.get(file_endpoint, headers=file_headers)
            # load file output to a python object
            file_details = json.loads(file_response.text)   

            # ignore Exceptions being outputted to user.    
            # check 'error' key in Json output, if True, file hasnt been submitted to any engines yet
            if 'error' in file_details:
                # call function from data_visualization module
                dv.draw_pie(labels=['No Threat Detected'], values=[100], colors = ['green'])
                file_is_not_suspicious=[uploaded_file_hash,'No threat detected']
                st.write(pd.DataFrame(file_is_not_suspicious, index=['File Hash', 'File Status'], columns=['Details']) )
            
            else:
                # lists to hold file details
                file_is_suspicious=[file_details['data']['attributes']['meaningful_name'],file_details['data']['attributes']['md5'],file_details['data']['attributes']['magic'],file_details['data']['attributes']['size']]
                if file_details['data']['attributes']['total_votes']['malicious'] == 0:
                    file_is_suspicious.append("No Threat Detected") 
                else:
                    file_is_suspicious.append("Threat Detected")

                scanned_file_engines = file_details['data']['attributes']['last_analysis_results']
                # iterate through nested dictionary to count number of engines that detected, don't support and/or undetected
                enumer_file_engines = []
                for i in scanned_file_engines.keys():
                    for values in scanned_file_engines[i].values():
                        enumer_file_engines.append(values)
                
                # number of detected, undetected and unsupported engines, used in donut piechart
                undetected= enumer_file_engines.count('undetected')
                detected= enumer_file_engines.count('detected')
                unsupported= enumer_file_engines.count('type-unsupported')
                
                # draw donut-shaped pie chart        
                dv.draw_pie(labels=['Detected threats', 'Undetected Threats', 'File scan Unsupported'],
                        values=[detected, undetected,unsupported], colors = ['red', 'green', 'white'])
                # draw a stackad horizontal bar with text
                dv.draw_stacked_bar(detected=detected, scanned_engines= undetected+detected+unsupported)
                
                st.info("Basic Properties")
                # draw table with column names and valuesf
                st.write(pd.DataFrame(file_is_suspicious, index=['File Name', 'File Hash', 'File Type', 'File Size', 'File Status'], columns=['Details']))

                st.info("Submission History")
                # Timestamps in file details is in Epoch time, seconds elapsed since 1/1/1997. 
                epoch_timestamp = [
                    (file_details['data']['attributes']['creation_date']),
                    (file_details['data']['attributes']['first_submission_date']),
                    (file_details['data']['attributes']['last_analysis_date']),            
                ]
                # convert epoch - normal time
                normal_timestamp = []
                for i in epoch_timestamp:
                    normal_timestamp.append(datetime.fromtimestamp(i))
                
                st.write(pd.DataFrame(normal_timestamp, index=['Creation Date','Submission Date','Last Analysis Date'], columns=['Dates']))
    except (ConnectionError):
        dv.svg_assets(image="Assets/404.svg")
        dv.page_404()
    except (NameError, KeyError):
        pass


# Cyber Intelligence Page.
if datavisual_choice == "Scan Credentials":
    st.markdown("**Choose tools from the dropdown**")
    tools_choice = st.selectbox("Cyber Intelligence Tools:",["—", "Email", "IP", "URL"])
            
    if tools_choice == "Email":
        try:
            st.markdown("Check your **Email** status against a collection of publically available data breaches")
            dv.svg_assets(image="Assets/inbox.svg")
            # E-mail API endpoint - 'http://emailrep.io/bsheffield432@gmail.com'
            email_input = st.text_input('Input Email')
            email_query = ['http://emailrep.io/']
            # append url with text_input data
            email_query.append(email_input)
            email_status = "".join(email_query)
            email_response = requests.get('{}'.format(email_status))
            email_details =json.loads(email_response.text)
            # st.write(email_details)
            # access values from *emails_details* JSON object
            # validate email input
            regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
            if (re.search(regex,email_input)):
                email_is_suspicious=[email_details['email'],email_details['suspicious'],email_details['details']['credentials_leaked'],email_details['details']['malicious_activity'],email_details['details']['spam']]
                #draw a table with *email_is_suspicious* dataframe    
                st.write(pd.DataFrame(email_is_suspicious, index=['Email','Suspicious','Credentials Leaked','Malicious', 'Spam'], columns=['Details']))
            elif not (re.search(regex,email_input)):
                st.error("Invalid Email, Check Email Again")
            elif 'fail' in email_details:
                st.error("Exceeded daily Limit. please wait 24 hrs or visit emailrep.io/key for an api key")
            elif len(email_input) == 0:
                pass
        except (KeyError,NameError):
            st.error("Invalid Email, Check Email Again")
        except (ConnectionError):
            dv.svg_assets(image="Assets/404.svg")
            dv.page_404()

    # IP 
    if tools_choice == "IP":        
        # IP API endpoint - http://api.cybercure.ai/feed/search?value=
        try:
            ip_input = st.text_input('Input IP Address',)
            # Create an instance of an ipdata object. Replace "config.ip_api_key" with your API Key
            ipdata = ipdata.IPData(ip_secret)
            ip_response = ipdata.lookup("{}".format(ip_input.lstrip()))
            # drawing IP locality map. Append Lat and Lon values to empty list
            geo_loc= [ip_response.get("latitude"),ip_response.get("longitude"),ip_response.get("country_name"),ip_response.get("city")]
            # verify from nested dictionary, to be included in "is_Threat" column in table 
            is_threat = ip_response["threat"]["is_known_attacker"]
            # 0 = Harmless , 1= Harmful        
            if is_threat == 0:
                geo_loc.append("No Threat Detected")
            else:
                geo_loc.append("Threat Detected")
                
            # draw table with column names and values
            ip_map = [geo_loc[0], geo_loc[1], geo_loc[2], geo_loc[3], geo_loc[4]]  
            if len(ip_input) == 0:
                pass 
            else:         
                st.success("Summary of IP Address: {}".format(ip_input))
                st.write(pd.DataFrame(ip_map, index=['Latitude','Longitude','Country','City', 'Threat Status'], columns=['Details']))
            
                # st.write(ip_response)
                # change above list to dataframe for web viewing
                ip_geo_values = pd.DataFrame(ip_map)
                st.info(("""**Please note**:The point-based map is interactive, you can zoom with scrolling and hover on data points."""))
                
            st.pydeck_chart(pdk.Deck(
            map_style='mapbox://styles/mapbox/dark-v9',
            initial_view_state=pdk.ViewState(
                latitude=ip_geo_values.at[0,0],
                longitude=ip_geo_values.at[1,0],
                zoom=11,
                pitch=50,
            ),
            layers=[
                pdk.Layer(
                    'HexagonLayer',
                    data=ip_geo_values,
                    get_position='[longitude, latitude]',
                    radius=200,
                    elevation_scale=4,
                    elevation_range=[0, 1000],
                    pickable=True,
                    extruded=True,
                ),
                pdk.Layer(
                    'ScatterplotLayer',
                    data=ip_geo_values,
                    get_position='[longitude, latitude]',
                    get_fill_color='[60, 220,255]',
                    get_radius=200,
                ),
            ],
            ))
        except ValueError:
            st.error(f"{ip_input}, Is an invalid IP address")
        except (ConnectionError):
            dv.svg_assets(image="Assets/404.svg")
            dv.page_404()
        except (NameError, KeyError):
            pass

    # URL 
    if tools_choice == "URL":
        try:
            # URL API endpoint
            url_endpoint = 'https://www.virustotal.com/vtapi/v2/url/report'
            url_input = st.text_input('Input URL',)
            #Replace `config.url_api` with your API Key
            url_params = {'apikey': url_secret, 'resource':url_input}
            url_response = requests.get(url_endpoint, params=url_params)
            #st.json(url_response.text) 
            url_details = json.loads(url_response.text)  
            scanned_url_engines = [url_details['scan_id'],url_details['url'],url_details['scan_date']]
            # validate URL input
            valid_url = validators.url(url_input)
            if valid_url==True:
                #visual components
                dv.draw_pie(labels=['Threats', 'No Threats'], values=[url_details['positives'],url_details['total']], colors=['red','green'])
                dv.draw_stacked_bar(detected=url_details['positives'], scanned_engines=url_details['total'])
                st.write(pd.DataFrame(scanned_url_engines, index=['Scan ID','URL Resource','Scan Date'], columns=['Details']))
        except KeyError:
            st.warning(f'Resource {url_input} does not exist in scanned engine\'s databases')
        except (ConnectionError):
            dv.svg_assets(image="Assets/404.svg")
            dv.page_404()
        except (NameError,TypeError, ValueError):
            pass
        
st.sidebar.header("Contribute")

st.sidebar.info(
    ("This is an open source project and you are very welcome to contribute your awesome comments, questions, resources and apps as issues of or pull requests to the source code ")
    + "[GitHub](https://github.com/NuhMohammed/ThreatSense)."
)


