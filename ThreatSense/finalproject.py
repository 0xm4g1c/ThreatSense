import streamlit as st
import pandas as pd
import plotly_express as px
import folium 
import seaborn as sns # plots histogram
import matplotlib.pyplot as plt # resize seaborn figure to be more readable
import requests
import pydeck as pdk
from folium.plugins import HeatMap
from PIL import Image
from ipdata import ipdata


st.title("ThreatSense :computer:")

# Caching -  reduce load time 
@st.cache(suppress_st_warning=True, hash_funcs={pd.core.frame.DataFrame: lambda _: None}, allow_output_mutation=True)
def load_data():
    uploaded_file = st.file_uploader("Choose a file..", type = "csv")
    if uploaded_file is not None:
        return uploaded_file

uploaded_file = load_data()


# sidebars

datavisual_choice = st.sidebar.radio("Navigate Pages",
("Home Page", "Compromised Credentials"))

# welcome page
if datavisual_choice == "Home Page":
    # call/load above function to a dataframe
    #if st.checkbox("Show first rows of the data"):
     #  st.write(data)
      #  st.write(data.shape) # returnd dimensionality of the dataframe (inside, outside)
    # Do not exhaust your free map reloads
    #if st.checkbox("Show Map"):
    #st.plotly_chart(display_map(data))
    st.header("**An Open-Source Attack Surface Management Framework**")
    st.subheader("**Find Technical Information About Internet Assets**")

    # home page promotional video
    src = "https://www.youtube.com/watch?v=wzsSkcgtDWo"
    st.video(src, start_time=0)
    
# Cyber Intelligence Page.
if datavisual_choice == "Compromised Credentials":
    
    tools_choice = st.selectbox("Cyber Intelligence Tools:",["Email", "IP", "URL"])

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
        st.write("Look up information about a specific IP:link: address")
        ip_input = st.text_input('Input IP Address',)
        # Create an instance of an ipdata object. Replace `test` with your API Key
        ipdata = ipdata.IPData('API_Key')
        # '69.78.70.144'
        ip_response = ipdata.lookup("{}".format(ip_input))
        st.write("**Notice**: **_Only public IP Addresses can be searched for now_**")

        #if st.checkbox("Show IP content(JSON):"):
        #    st.write("Collapse/Expand")
        #    st.write(ip_response) 

        # drawing IP locality map
        # Append Lat and Lon values to empty list
        geo_loc= []
        geo_loc.append(ip_response.get("latitude"))
        geo_loc.append(ip_response.get("longitude"))
        geo_loc.append(ip_response.get("country_name"))
        geo_loc.append(ip_response.get("city"))
        

        ip_map = [{'latitude':geo_loc[0], 'longitude':geo_loc[1],'country':geo_loc[2], 'city':geo_loc[3]}]

        # change list to dataframe
        ip_map = pd.DataFrame(ip_map)

        st.success("A summary of  IP Address {}".format(ip_input))
        st.dataframe(ip_map)

        st.pydeck_chart(pdk.Deck(
        map_style='mapbox://styles/mapbox/light-v9',
        initial_view_state=pdk.ViewState(
            latitude=ip_map.at[0,'latitude'],
            longitude=ip_map.at[0,'longitude'],
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
        params = {'apikey': 'test', 'resource':(url_input)}
        url_response = requests.get(url_endpoint, params=params)
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

