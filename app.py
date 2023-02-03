from flask import Flask, render_template
import pandas as pd
import plotly.express as px
from bs4 import BeautifulSoup
import sys
from pyvis.network import Network

from dash import Dash, html, dcc, Output, Input

df = pd.read_csv('static/website_data.csv')
df_flows = pd.read_csv('static/website_flow_data.csv')
df_flows_drop = df_flows.filter(regex='^all_', axis=1).columns.tolist()
df_flows_drop = [i[4:] for i in df_flows_drop]  # remove 'all_' to make use for other protocol filters
#df['date'] = pd.to_datetime(df['date'])
app = Flask(__name__)
i = 1


def create_dash_app(flask_app):
    dash_app = Dash(server=flask_app, name='dashboard', url_base_pathname='/dash/')
    dash_app.layout = html.Div(
        html.Div([
            dcc.Graph(
                id='main_graph_line',
                figure=px.line(df, x='date', y=df.columns.values.tolist()[1:6], title='H-CyTE Stuff')  # TODO: FIX FROM HARD CODE COL CALL
                    .update_xaxes(rangeslider_visible=True)
                    .update_layout(width=1200, height=400, clickmode='event+select').update_traces(marker_size=20),
                style={
                    "width": "100%",
                    "height": "400px",
                    "display": "inline-block",
                    "padding-top": "5px",
                    "padding-left": "1px",
                }
            ),
            html.Div([html.Div(html.B('Total Alerts:'), style={'margin-right': '15px', 'display': 'inline-block'}), html.Div(id='total_value', style={'display': 'inline-block'}),
                      html.Div(dcc.Dropdown(
                          df_flows_drop,
                          'num_flows',
                          id='yaxis-column'), style={'width': '48%', 'float': 'right', 'display': 'inline-block'})
                      ], style={'margin-bottom': '20px'}),
            html.Div([html.Div(dcc.Graph(id='secondary_graph_pie'), style={'width': '50%', 'display': 'inline-block'}),
                      html.Div(dcc.Graph(id='secondary_graph_flow'), style={'width': '50%', 'display': 'inline-block'})]),

        ])

    )
    return dash_app


dash_app = create_dash_app(flask_app=app)
dash_app.scripts.config.serve_locally = True

curve_nums = {
    0: 'scan_num',
    1: 'all_alerts',
    2: 'ssh_telnet_alerts',
    3: 'http_alerts',
    4: 'rtsp_alerts'
}

flow_titles = {
    'scan_num': 'scan_flows',
    'all_alerts': 'all_flows',
    'ssh_telnet_alerts': 'ssh/telnet flows',
    'http_alerts': 'http_flows',
    'rtsp_alerts': 'rtsp_flows'
}
flow_y = {
    'scan_num': 'all_',
    'all_alerts': 'all_',
    'ssh_telnet_alerts': 'ssh_tel_',
    'http_alerts': 'http_',
    'rtsp_alerts': 'rtsp_'
}


@dash_app.callback(
    Output(component_id='secondary_graph_flow', component_property='figure'),
    Input(component_id='yaxis-column', component_property='value'),
    Input(component_id='main_graph_line', component_property='hoverData'),
    Input(component_id='main_graph_line', component_property='clickData'))
def displayHoverFlowGraph(yaxis_column_name=None, hoverData=None, clickData=None):
    if hoverData is not None:
        curve = curve_nums[hoverData['points'][0]['curveNumber']]
    elif clickData is not None:
        curve = curve_nums[clickData['points'][0]['curveNumber']]
    else:
        curve = curve_nums[1]

    if curve == 'scan_num':
        curve = 'all_alerts'  # no scan flows at this time
    curve_regex = '^{}_'.format(curve.split('_')[0])
    df1 = df_flows.filter(regex=curve_regex, axis=1)  # TODO: NEW CSV WITH FLOW DATA, REPLACE DF WITH
    df1.insert(0, 'date', df_flows['date'].values.tolist())
    y_name = flow_y[curve] + yaxis_column_name

    fig = px.line(data_frame=df1, title='flow data: {}'.format(flow_titles[curve]),
                  hover_name='date', hover_data=df1.columns.tolist(), x='date', y=y_name).update_xaxes(rangeslider_visible=True)
    return fig


@dash_app.callback(
    Output(component_id='total_value', component_property='children'),
    Output(component_id='secondary_graph_pie', component_property='figure'),
    Input(component_id='main_graph_line', component_property='hoverData'),
    Input(component_id='main_graph_line', component_property='clickData'))
def displayHoverDataGraph(hoverData=None, clickData=None):
    if hoverData is not None:
        date1 = hoverData['points'][0]['x']
        curve = curve_nums[hoverData['points'][0]['curveNumber']]
        df1 = df.loc[df['date'] == date1]

    elif clickData is not None:
        date1 = clickData['points'][0]['x']
        curve = curve_nums[clickData['points'][0]['curveNumber']]
        df1 = df.loc[df['date'] == date1]

    else:
        date1 = "2023-01-04"
        # TODO: CHANGE TO dt.date.today() - timedelta(days=1) when day to day updating is implemented
        curve = curve_nums[1]
        df1 = df.loc[df['date'] == date1]

    if curve != 'all_alerts':
        curve_regex = '^{}_'.format(curve.split('_')[0])
        # If not all, can apply strict regex based on first word. Otherwise, need to be more casual (but still get rud of flow stuff when added)
        curve_columns = df1.filter(regex=curve_regex, axis=1).columns.tolist()  # regex for first word as id as enumerated in curve_nums
        total = df1[curve_columns[0]]  # Will be first one since line columns are first in df
        subtotals = curve_columns[1:]  # may not add up until all alerts are enumerated (PAIN IN THE ASS)
    else:
        # all alerts curve selected
        curve_columns = df1.drop(columns=['date'], axis=1).drop(
            columns=df1.filter(regex='^scan_', axis=1).columns.tolist(), axis=1)
        # Remove date and scan (not relevant results (remove flow when added as well if not stored in seperate csv)
        total = curve_columns['all_alerts']

        sub_col_list = list(curve_nums.values())
        sub_col_list.remove('scan_num')  # Need to remove since key error (scan_num dropped by filter)
        subtotals = curve_columns.drop(columns=sub_col_list,
                                       axis=1).columns.tolist()  # may not add up until all alerts are enumerated (PAIN IN THE ASS)
        # Drop less stringent columns that make up main line graph

    df_filtered = df1[subtotals]
    df_filt_dict = df_filtered.to_dict('records')[0]
    fig = px.pie(data_frame=df1, title="{} Expanded: {}".format(curve, date1), names=df_filt_dict.keys(),
                 values=df_filt_dict.values()).update_traces(hoverinfo='label+percent')
    return total, fig


@app.route('/', strict_slashes=False, methods=["GET"])
@app.route('/macro', strict_slashes=False, methods=["GET"])
def macro():

    dash_ht = dash_app.index()

    return render_template('macro.html', dash_html=dash_ht)


@app.route('/micro', strict_slashes=False)
def micro():
    #vis_html = None
    net = Network(filter_menu=True, select_menu=True)
    srcIPs = []
    destIPs = []
    classifications = []
    descriptions = []
    def getDescription(splitString, index):
        description = ""
        for i in range(len(splitString)):
            currentWord = splitString[index]
            while(currentWord[-1] != ']'):
                description = "{} ".format(currentWord) + description
                index -= 1
                currentWord = splitString[index]
            print("Final description: " + description)
            return(description)

    alerts = open(sys.argv[1], 'r')
    counter = 0
    for line in alerts:
        print(line)
        splitString = line.split(" ")
        print(splitString)
        destIP = ""
        srcIP = "" 
        classification = ""
        priority = 0
        color = ""
        #loop through each line and extract the valuable info
        for i in range(len(splitString)):
            #get the src and dest IPs
            if(splitString[i] == '{TCP}' or splitString[i] == '{UDP}' or splitString[i] == '{ICMP}'):
                srcIPandPort = splitString[i+1]
                srcIPandPort = srcIPandPort.split(":")
                srcIP = srcIPandPort[0]

                if(len(srcIPandPort) > 1):
                    srcPort = srcIPandPort[1]
                #if the length is equal to 1, there is no port number specified in the alert
                else:
                    srcPort = ''

                destIPandPort = splitString[i+3]
                destIPandPort = destIPandPort.split(":")
                destIP = destIPandPort[0]
                
                if(len(destIPandPort) > 1):
                    destPort = destIPandPort[1]
                else:
                    destPort = ''

                #print("Source IP: " + srcIP)
                #print("Source port: " + srcPort)
                #print("Dest IP: " + destIP)
                #print("Dest port: " + destPort)
            j = i
            #get the alert classification
            if(splitString[i] == "[Classification:"):
                j += 1
                currentWord = splitString[j]
                while(currentWord[-1] != "]"):
                    #print("Current word: " + currentWord)
                    classification += currentWord + " " 
                    j += 1
                    currentWord = splitString[j]
                classification += currentWord[:-1]
                description = getDescription(splitString, i-2)
            #get the priority of the alert
            if(splitString[i] == "[Priority:"):
                priority = splitString[i+1][:-1]
        #set the color of the node based on the priority
        if(priority == '1'):
            color = 'red'
        elif(priority == '2'):
            color = 'orange'
        else:
            color = 'blue'
        #add src node and dest node to the network and draw an edge between them
        if(destPort == ''):
            print("Port not specified")
        #only create the node if the destination port is common
        elif(int(destPort) < 1024):
            print("Port is common: " + str(destPort))
            net.add_node(srcIP + ":" + srcPort, label="Src: " + srcIP + ":" + srcPort, title=classification + ": " + description, color=color)
            net.add_node(destIP, label="Dest: " + destIP, title="Dest IP")
            net.add_edge(srcIP + ":" + srcPort, destIP, label=destPort)
            #add the info to the lists for the text visualization
            srcIPs.append(srcIP)
            destIPs.append(destIP)
            descriptions.append(description)
            classifications.append(classification)
        else:
            print("Port is not common: " + str(destPort))
            
    #create the network HTML file

    #This line is used to customize the physics
    #net.show_buttons(filter_=['physics'])

    #net.save_graph("testAttackPort.html")

    print("Printing generate html")
    print(net.generate_html())

    with open("testAttackPort.html") as inf:
        txt = inf.read()
        soup = BeautifulSoup(txt, 'html.parser')
    soup.body.decompose()
    print(soup.prettify())
    vis_html = soup.prettify()


    return render_template('micro.html', vis_html=vis_html)


@app.route('/about', strict_slashes=False)
def about():
    return render_template('about.html')


@app.route('/contact', strict_slashes=False, methods=["GET"])
def contact():
    return render_template('contact.html')


if __name__ == '__main__':
    app.run(port=80)
