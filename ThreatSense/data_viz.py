import app
import plotly.graph_objects as go


# file upload 
def file_visualization():
    fig = go.Figure(go.Indicator(
    mode = "gauge+number",
    value = 270,
    domain = {'x': [0, 1], 'y': [0, 1]},
    title = {'text': "Scanned Engines"}))
    return fig.show()

print(file_visualization())