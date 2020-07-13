import streamlit as st
import pandas as pd
import plotly_express as px
import requests
import pydeck as pdk
import config
import hashlib
import json
from folium.plugins import HeatMap
from PIL import Image
from ipdata import ipdata
import numpy as np


st.title("ThreatSense :computer:")

# sidebars
datavisual_choice = st.sidebar.radio("Navigate Pages",
("Home Page", "File Upload", "Compromised Credentials"))

# welcome page
if datavisual_choice == "Home Page":
    st.header("**An Open-Source Attack Surface Management Framework**")
    st.subheader("**Find Technical Information About Internet Assets**")
    # home page promotional video
    src = "https://www.youtube.com/watch?v=wzsSkcgtDWo"
    st.video(src, start_time=0) 

if datavisual_choice =="File Upload":
    # Caching -  reduce load time 
    uploaded_file = st.file_uploader("Choose a file to scan..")    
    if uploaded_file is not None:
        # getting hash value of uploaded file
        bytes = uploaded_file.read()
        uploaded_file_hash = hashlib.md5(bytes).hexdigest()
        # add hash to endpoint
        file_endpoint = "https://www.virustotal.com/api/v3/files/" +  uploaded_file_hash
        file_headers = {'x-apikey': config.file_api_key}
        file_response = requests.get(file_endpoint, headers=file_headers)
        # modify file output to show: Hash value, file type, file name, submission period
        # load file output to a python object
        file_details = json.loads(file_response.text)
        #st.json(file_details)
        st.success("Basic Properties")
        # check 'error' key in Json output, if True, file is safe
        key = 'error'
        if key in file_details:
            st.write(pd.DataFrame({
                'File Hash':[uploaded_file_hash],
                'File Status':['Harmless']
            }))
        else:
            # lists to hold file details
            properties=[]
            properties.append(file_details['data']['attributes']['meaningful_name'])
            properties.append(file_details['data']['attributes']['md5'])
            properties.append(file_details['data']['attributes']['magic'])
            properties.append(file_details['data']['attributes']['size'])
            if file_details['data']['attributes']['total_votes']['malicious'] == 0:
                properties.append("Harmless") 
            else:
                properties.append("Harmful")

            # draw table with column names and values
            # change list to dataframe
            st.write(pd.DataFrame({
                "File Name":[properties[0]],
                "File Hash":[properties[1]],
                "File Type":[properties[2]],
                "File Size":[properties[3]],
                "File Status":[properties[4]]
            }))
        
# Cyber Intelligence Page.
if datavisual_choice == "Compromised Credentials":
    st.markdown("**Choose tools from the dropdown**")
    tools_choice = st.selectbox("Cyber Intelligence Tools:",["—", "Email", "IP", "URL"])
            
    if tools_choice == "Email":
        st.markdown("Check your **Email** status against a collection of publically available data breaches")
        # E-mail API endpoint - 'http://emailrep.io/bsheffield432@gmail.com'
        email_input = st.text_input('Input Email')
        email_query = ['http://emailrep.io/']
        # append url with text_input data
        email_query.append(email_input)
        email_status = "".join(email_query)
        email_response = requests.get('{}'.format(email_status))
        st.json(email_response.text)

    if tools_choice == "IP":
        # IP API endpoint - http://api.cybercure.ai/feed/search?value=
        ip_input = st.text_input('Input IP Address',)
        # Create an instance of an ipdata object. Replace "config.ip_api_key" with your API Key
        ipdata = ipdata.IPData(config.ip_api_key)
        ip_response = ipdata.lookup("{}".format(ip_input))
        st.write("Look up information about a specific IP:link: address")
        st.write("**Notice**: **_Only public IP Addresses can be searched for now_**")

        if st.checkbox("Show IP content(JSON):"):
            st.write(ip_response) 

        # verify from nested dictionary, to be included in "is_Threat" column in table 
        is_threat = ip_response["threat"]["is_known_attacker"]
            
        # drawing IP locality map
        # Append Lat and Lon values to empty list
        geo_loc= []
        geo_loc.append(ip_response.get("latitude"))
        geo_loc.append(ip_response.get("longitude"))
        geo_loc.append(ip_response.get("country_name"))
        geo_loc.append(ip_response.get("city"))
        # 0 = Harmless , 1= Harmful
        if is_threat == 0:
            geo_loc.append("Harmless")
        else:
            geo_loc.append("Harmfull")

        # draw table with column names and values
        ip_map = [{'latitude':geo_loc[0], 'longitude':geo_loc[1],'country':geo_loc[2], 'city':geo_loc[3], 'is_Threat':geo_loc[4]}]

        # change list to dataframe
        ip_values = pd.DataFrame(ip_map)
        st.success("A summary of  IP Address {}".format(ip_input))
        st.dataframe(ip_values)

        if st.checkbox("Show IP content(Map):"):
            st.pydeck_chart(pdk.Deck(
            map_style='mapbox://styles/mapbox/dark-v9',
            initial_view_state=pdk.ViewState(
                latitude=ip_values.at[0,'latitude'],
                longitude=ip_values.at[0,'longitude'],
                zoom=11,
                pitch=50,
            ),
            layers=[
                pdk.Layer(
                    'HexagonLayer',
                    data=ip_map,
                    get_position='[longitude, latitude]',
                    radius=200,
                    elevation_scale=4,
                    elevation_range=[0, 1000],
                    pickable=True,
                    extruded=True,
                ),
                pdk.Layer(
                    'ScatterplotLayer',
                    data=ip_map,
                    get_position='[longitude, latitude]',
                    get_fill_color='[60, 220,255]',
                    get_radius=200,
                ),
            ],
        ))

    # recent scans
    
    if tools_choice == "URL":
        # URL API endpoint
        url_endpoint = 'https://www.virustotal.com/vtapi/v2/url/report'
        url_input = st.text_input('Input URL',)
        #Replace `test` with your API Key
        url_params = {'apikey': config.url_api_key, 'resource':url_input}
        url_response = requests.get(url_endpoint, params=url_params)
        st.json(url_response.text)

st.sidebar.info((
    """
**Please note**:
The point-based map is interactive, you can zoom with scrolling and hover on data points for additional information.
"""
))

st.sidebar.header("Contribute")
st.sidebar.info(
    ("This is an open source project and you are very welcome to contribute your awesome comments, questions, resources and apps as issues of or pull requests to the source code ")
    + "[GitHub](https://github.com/NuhMohammed/ThreatSense)."
)

