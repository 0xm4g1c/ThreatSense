# refactor code. 
# separate visualization code from app.py
# following software guideline, DRY: Dont Repeat Yourself (DRY). 
import streamlit as st
import plotly.graph_objects as go

# donut-shaped charts used to show asset threat severity
def draw_pie(labels, values):
    pie_figure = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.5)])
    pie_figure.update_layout(
    autosize=False,
    width=500,
    height=250
    )
    return st.plotly_chart(pie_figure)

# labels and values should be contained in a list [] e.g. draw_pie(labels = ['Unknown File'], values = [100])

    

