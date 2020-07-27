import streamlit as st
import pandas as pd
import requests
import pydeck as pdk
import config
import hashlib
import json
import re
import plotly.graph_objects as go
from PIL import Image
from ipdata import ipdata
from datetime import datetime, date

st.title("ThreatSense :computer:")

# sidebars
datavisual_choice = st.sidebar.radio("Navigate Pages",
("Home Page", "File Upload", "Compromised Credentials"))

# welcome page
if datavisual_choice == "Home Page":
    st.header("**Vulnerability Scanner for everyone**")
    st.subheader("Find technical information about internet assets before **_HACKERS_** do")
    # home page promotional video
    #src = "https://www.youtube.com/watch?v=wzsSkcgtDWo"
    #st.video(src, start_time=0) 

    st.markdown(f"<center> Core features </center", unsafe_allow_html=True)
    image_hiw = Image.open('hiw2.jpg')
    st.image(image_hiw, use_column_width=True)

# File upload
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

        # check 'error' key in Json output, if True, file is safe
        key = 'error'
        if key in file_details:
            safe_labels = ['Unknown File']
            safe_values = [100]
            safe_pie_figure= go.Figure(data=[go.Pie(labels=safe_labels,values=safe_values,hole=.4)])
            safe_pie_figure.update_layout(
                autosize=False,
                width=500,
                height=250
            )
            st.plotly_chart(safe_pie_figure)
            file_is_not_suspicious=[uploaded_file_hash,'Unknown File']
            st.write(pd.DataFrame(file_is_not_suspicious, index=['File Hash', 'File Status'], columns=['Details']) )
        
        else:
            # lists to hold file details
            file_is_suspicious=[file_details['data']['attributes']['meaningful_name'],file_details['data']['attributes']['md5'],file_details['data']['attributes']['magic'],file_details['data']['attributes']['size']]
            if file_details['data']['attributes']['total_votes']['malicious'] == 0:
                file_is_suspicious.append("Harmless") 
            else:
                file_is_suspicious.append("Harmful")

            scanned_engines = file_details['data']['attributes']['last_analysis_results']
            # iterate through nested dictionary to count number of engines that detected, don't support and/or undetected
            enumer_engines = []
            for i in scanned_engines.keys():
                for values in scanned_engines[i].values():
                    enumer_engines.append(values)
            
            # number of detected, undetected engines, used in donut piechart
            undetected= enumer_engines.count('undetected')
            detected= enumer_engines.count('detected')
            unsupported= enumer_engines.count('type-unsupported')
            
            # draw donut-shaped pie chart
            suspicious_labels = ['Detected threats', 'Undetected Threats', 'File scan Unsupported']
            suspicious_values = [detected, undetected,unsupported]
            suspicious_pie_figure = go.Figure(data=[go.Pie(labels=suspicious_labels, values=suspicious_values, hole=.5)])
            suspicious_pie_figure.update_layout(
                autosize=False,
                width=500,
                height=250
            )
            st.plotly_chart(suspicious_pie_figure)

            # draw a stackad horizontal bar with text
            st.markdown(f'''
                <div class="card text-white bg-info mb-3"  style="width: 28rem", centered>
                    <div class="card-header">
                        File Severity
                    </div>
                    <div class='card-body'>
                        <p class="card-text">{undetected} / {len(scanned_engines)} scanned engines did not detect any threats</p>
                    </div>
                </div>''', unsafe_allow_html=True)
            
            st.success("Basic Properties")
            # draw table with column names and valuesf
            st.write(pd.DataFrame(file_is_suspicious, index=['File Name', 'File Hash', 'File Type', 'File Size', 'File Status'], columns=['Details']))

            st.success("Submission History")
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

            pd.set_option('display.expand_frame_repr', True)
            st.write(pd.DataFrame(normal_timestamp, index=['Creation Date','Submission Date','Last Analysis Date'], columns=['Dates']))



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
        email_details =json.loads(email_response.text)
        # access values from *emails_details* JSON object
        # validate email input
        regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
        if (re.search(regex,email_input)):
            email_is_suspicious=[email_details['email'],email_details['suspicious'],email_details['details']['credentials_leaked'],email_details['details']['malicious_activity'],email_details['details']['spam']]
            #draw a table with *email_is_suspicious* dataframe    
            st.write(pd.DataFrame(email_is_suspicious, index=['Email','Suspicious','Credentials Leaked','Malicious', 'Spam'], columns=['Details']))
        elif 'fail' in email_details:
            st.error("Exceeded daily Limit. please wait 24 hrs or visit emailrep.io/key for an api key")
        elif len(email_input) == 0:
            pass
        else:
            st.error("Invalid Email, Check Email Again")


    if tools_choice == "IP":
        # IP API endpoint - http://api.cybercure.ai/feed/search?value=
        ip_input = st.text_input('Input IP Address',)
        # Create an instance of an ipdata object. Replace "config.ip_api_key" with your API Key
        ipdata = ipdata.IPData(config.ip_api_key)
        ip_response = ipdata.lookup("{}".format(ip_input))
        st.write("**Notice**: **_Only public IP Addresses can be searched for now_**")
        # drawing IP locality map. Append Lat and Lon values to empty list
        geo_loc= [ip_response.get("latitude"),ip_response.get("longitude"),ip_response.get("country_name"),ip_response.get("city")]
        # verify from nested dictionary, to be included in "is_Threat" column in table 
        is_threat = ip_response["threat"]["is_known_attacker"]
        # 0 = Harmless , 1= Harmful
        if is_threat == 0:
            geo_loc.append("Harmless")
        else:
            geo_loc.append("Harmfull")

        # draw table with column names and values
        ip_map = [geo_loc[0], geo_loc[1], geo_loc[2], geo_loc[3], geo_loc[4]]
        st.success("A summary of  IP Address {}".format(ip_input))
        st.write(pd.DataFrame(ip_map, index=['Latitude','Longitude','Country','City', 'Threat'], columns=['Details']))
    
        if st.checkbox("Show IP content(JSON):"):
            st.write(ip_response)
        # change above list to dataframe for web viewing
        ip_geo_values = pd.DataFrame(ip_map)
        if st.checkbox("Show IP content(Map):"):
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
        st.info((
            """
        **Please note**:
        The point-based map is interactive, you can zoom with scrolling and hover on data points for additional information.
        """
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


st.sidebar.header("Contribute")
st.sidebar.info(
    ("This is an open source project and you are very welcome to contribute your awesome comments, questions, resources and apps as issues of or pull requests to the source code ")
    + "[GitHub](https://github.com/NuhMohammed/ThreatSense)."
)

