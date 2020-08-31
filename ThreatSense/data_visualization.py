# refactor code. 
# separate visualization code from app.py
# following software guideline, DRY: Dont Repeat Yourself (DRY). 
import streamlit as st
import plotly.graph_objects as go
from PIL import Image
import base64
import textwrap

# donut-shaped charts used to show asset threat severity
# labels and values should be contained in a list [] e.g. draw_pie(labels = ['Unknown File'], values = [100])
def draw_pie(labels, values, colors):
    pie_figure = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.5)])
    pie_figure.update_layout(
    autosize=False,
    width=500,
    height=350
    )
    pie_figure.update_traces(
        textposition = 'inside',
        marker = dict(colors=colors, line=dict(color='#000000', width=1))
    )
    return st.plotly_chart(pie_figure)


def draw_stacked_bar(detected, scanned_engines):
    return st.markdown(f'''
                    <div class="card text-black bg-light mb-3"  style="width: 43.5rem; height:6rem; font-size:13px">
                        <div class="card-header">
                            Analysis Summary
                        </div>
                        <div class='card-body'>
                            <p class="card-text">{detected} / {scanned_engines} scanned engines detected threats</p>
                        </div>
                    </div>''', unsafe_allow_html=True)

def show_vid():
    # home page promotional video
    src = "https://www.youtube.com/watch?v=wzsSkcgtDWo"
    return st.video(src, start_time=0)

# render svg assets in welcome page
def render_svg(svg):
    b64 = base64.b64encode(svg.encode('utf-8')).decode("utf-8")
    html = r'<img src="data:image/svg+xml;base64,%s"/>' % b64
    return st.write(html, unsafe_allow_html=True)

def svg_assets(image):
        svg = open(image,"r")
        lines = svg.readlines()
        line_string=''.join(lines)
        render_svg(line_string)


def threatmap():
    return st.markdown(f'''
        <iframe width="620" height="350" 
         src="https://cybermap.kaspersky.com/en/widget/dynamic/dark"
         frameborder="10">
    ''', unsafe_allow_html=True)


# Future Work, subsequent releases.
# navigation
