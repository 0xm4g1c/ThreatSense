# refactor code. 
# separate visualization code from app.py
# following software guideline, DRY: Dont Repeat Yourself (DRY). 
import streamlit as st
import plotly.graph_objects as go

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


# Future Work, subsequent releases.
# navigation
def draw_tabs():
    return st.markdown(f'''
                     <ul class="nav nav-pills">
                        <li class="active"><a href="#">Basic Properties</a></li>
                        <li><a href= "#">Submission History</a></li>
                    </ul>''', 
                    unsafe_allow_html=True)
