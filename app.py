import csv
import datetime as dt
import math
import re
import time

from flask import Flask, render_template, redirect, url_for, request
import pandas as pd
import plotly.express as px
from dash import Dash, html, dcc, Output, Input
from dash.exceptions import PreventUpdate
import visdcc
from netaddr import IPNetwork

from webApp import forms
from webApp.flow import Flow

visdcc_display_dict = {'internal': {},
                       'external': {},
                       'tap': {}}
micro_int_files = {'internal': '/var/www/webApp/webApp/static/int_micro_live.csv',
                   'external': '/var/www/webApp/webApp/static/ext_micro_live.csv',
                   'tap': '/var/www/webApp/webApp/static/tap_micro_live.csv'}
active_int = 'internal'

scans_dict = {}
sweeps_dict = {}
sweepNodes = []
scanNodes = []

current_data = {'nodes': [], 'edges': []}

home_net = IPNetwork("192.168.50.0/24")
home_ext = IPNetwork("64.183.181.215/32")
multi_net = IPNetwork("224.0.0.0/4")
broad_net = IPNetwork("255.255.255.0/24")
broad_inner = IPNetwork("192.168.50.255/32")


app = Flask(__name__)
app.config['SESSION_COOKIE_SAMESITE'] = "Secure"
app.config['SECRET_KEY'] = 'b6821eaa9fce8996030370c7831fd2cc2d7a509254551bdb'

app.config['RECAPTCHA_USE_SSL'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = '6Ld81k4kAAAAAHaEuoxKtg7N2QE11yjP3ySy8X-U'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6Ld81k4kAAAAANDMNw2lbt5hzjXg71XbErsN37S3'
# TODO: REGENERATE WHEN LIVE HOSTING  https://www.google.com/recaptcha/admin/create
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')


#df = pd.read_csv('static/website_data.csv')
#df_flows = pd.read_csv('static/website_flow_data.csv')
#live_micro_file = 'static/micro_live.csv'
# TODO: CHANGE TO STATIC /var/www/webApp/webApp/static
df = pd.read_csv('/var/www/webApp/webApp/static/website_data.csv')
df_flows = pd.read_csv('/var/www/webApp/webApp/static/website_flow_data.csv')

df_flows_drop = df_flows.filter(regex='^all_', axis=1).columns.tolist()
df_flows_drop = [i[4:] for i in df_flows_drop]  # remove 'all_' to make use for other protocol filters


def get_anonymized_label(addr: str):
    addr_type = 1  # 1 = outside home sub, 2 = inside home/net, 3 = broad/multicast
    if (addr in home_net or addr in home_ext) and addr not in broad_inner:
        addr_type = 2
    elif addr in multi_net or addr in broad_net or addr in broad_inner:
        addr_type = 3

    if addr not in home_net and addr not in multi_net and addr not in broad_net and addr not in broad_inner:
        IP_label_split = addr.split('.')
        for i in range(len(IP_label_split)):
            IP_label_split[i] = IP_label_split[i][:-1] + 'X'
        IP_label = '.'.join(IP_label_split)
    else:
        IP_label = addr
    return IP_label, addr_type


micro_node_color_code = {
    1: 'yellow',
    2: 'green',
    3: 'purple',
    4: 'orange',
    5: 'red'
}


def create_dash_micro(flask_app):
    external_stylesheets = ['https://cdnjs.cloudflare.com/ajax/libs/vis/4.20.1/vis.min.css']
    dash_app1 = Dash(server=flask_app, name='dashboard1', url_base_pathname='/dash1/',
                     external_stylesheets=external_stylesheets)

    dash_app1.layout = html.Div([html.Div(html.B(id='num_flows')), html.Div(dcc.Checklist(id='live_check', options=[{'label': 'Live Feed', 'value': 'live'}],
                                                        value=['live'])),
                                 html.Div([html.Div(html.B('Displayed Nodes'), style={'display': 'inline-block', 'padding-right': '5px'}),
                                     dcc.Checklist(id='vis_filter', options=
                                 [{'label': 'Internal', 'value': 'internal'},
                                  {'label': 'External', 'value': 'external'},
                                  {'label': 'Multi/Broadcast', 'value': 'multi'},
                                  {'label': 'Internal Suspicious Nodes', 'value': 'internal_suspicious'},
                                  {'label': 'External Suspicious Nodes', 'value': 'external_suspicious'}],
                                                        value=['internal', 'external', 'multi', 'internal_suspicious', 'external_suspicious'],style={'display': 'inline-block'}),]),

                                 html.Div([html.Div(html.B('Protocol'), style={'display': 'inline-block', 'padding-right': '5px'}),
                                 html.Div(dcc.Checklist(id='proto_filter', options=
                                 [{'label': 'TCP', 'value': 'tcp'},
                                  {'label': 'UDP', 'value': 'udp'}],
                                                        value=['tcp', 'udp']), style={'display': 'inline-block', 'padding-right': '10px'}),
                                           html.Div(html.B('Interface'), style={'display': 'inline-block', 'padding-right': '5px'}),
                                           html.Div(dcc.Dropdown(id='interface_dropdown',
                                                        options=[
                                                            {'label': 'Internal Interface', 'value': 'internal'},
                                                            {'label': 'External Interface', 'value': 'external'},
                                                            {'label': 'WiFi Tap Interface', 'value': 'tap'},
                                                        ],
                                                        value='internal', style={'position':'relative', 'top': '5px'}
                                                        ), style={'width': '30%', 'display': 'inline-block', 'padding-right': '5px'}),
                                           html.Div(html.B('Note: Tap Interface Prone to breaking'), style={'display': 'inline-block'})]),

                                 html.Div([
                                           html.Div(html.B('Packets In Flow (WARNING: VALUE < 4 MAY RESULT IN PERFORMANCE LOSS FROM INCOMPLETE FLOWS)')),
                                           html.Div(dcc.Slider(1, 1000, 1, value=4, marks=None,
                                                     tooltip={"placement": "bottom", "always_visible": True}, id='flow_slider'))
                                           ]),

                                 visdcc.Network(id='net',
                                                #data=current_data,
                                                selection = {'nodes':[], 'edges':[]},
                                                options=dict(height='1200px', width='100%', layout={
                                                    'improvedLayout': True,
                                                    'hierarchical': {
                                                        'enabled': False,
                                                        'blockShifting': True,
                                                        'edgeMinimization': True
                                                    }
                                                }, physics={
                                                    'enabled': True,
                                                    'maxVelocity': 25,
                                                    'solver': 'barnesHut',
                                                    'barnesHut': {
                                                        'gravitationalConstant': -1000,
                                                        'centralGravity': 0.85,
                                                        'springLength': 95,
                                                        'springConstant': 0.02,
                                                        'damping': 0.09,
                                                        'avoidOverlap': 0
                                                    },
                                                    'stabilization': {
                                                        'enabled': True,
                                                        'iterations': 1000,
                                                        'updateInterval': 100,
                                                        'onlyDynamicEdges': False,
                                                        'fit': True
                                                    }
                                                }
                                                             )),

                                 dcc.Interval(
                                     id='interval_component',
                                     interval=5 * 1000,  # in milliseconds
                                     n_intervals=0
                                 ), html.Div(id='hidden_div', style={'display': 'none'}),
                                 html.Div(id='nodes'),
                                 html.Div(id='edges')
                                 ])

    return dash_app1

"""
layout={
'improvedLayout': True,
'hierarchical': {
'enabled': False,
'blockShifting': True,
'edgeMinimization': True,
'parentCentralization': True,
'direction': 'UD',  # UD, DU, LR, RL
'sortMethod': 'hubsize'  # hubsize, directed
}}
"""


dash_app_micro = create_dash_micro(flask_app=app)
dash_app_micro.scripts.config.serve_locally = True


def csv_to_flow_dict(live_micro_file):
    ret_dict = {}
    with open(live_micro_file, 'r') as f:
        cols = list(Flow.__dict__.keys())[3:64]
        cols.insert(0, 'empty')  # for key
        r_obj = csv.reader(f)
        rows = list(r_obj)
        read_rows = 0

        for row in rows:
            if read_rows != 0:  # skip header
                key = row[0]
                temp_flow = Flow()
                for col in range(1, len(cols)):
                    try:
                        setattr(temp_flow, cols[col], row[col])
                    except IndexError:
                        #print('ERROR: BAD FILE READ AT {}: INCOMPLETE FLOW ENTRY'.format(live_micro_file))
                        read_rows += 1
                        continue  # incomplete row from WAR/concurrent access with sniffer, throw out
                ret_dict[key] = temp_flow
            read_rows += 1
    return ret_dict




@dash_app_micro.callback(
    Output(component_id='net', component_property='data'),
    Output(component_id='num_flows', component_property='children'),
    Input(component_id='interval_component', component_property='n_intervals'),
    Input(component_id='live_check', component_property='value'),
    Input(component_id='vis_filter', component_property='value'),
    Input(component_id='proto_filter', component_property='value'),
    Input(component_id='flow_slider', component_property='value'),
    Input(component_id='interface_dropdown', component_property='value')
)
def build_visdcc(n_intervals=None, live_check=None, vis_filter=None, proto_filter=None, flow_slider=None, interface_dropdown=None):
    global active_int
    print("Running build function")
    # create visdcc thing here
    srcIPs = []
    destIPs = []
    edges = []
    nodes = []


    # switches match with codes returned from anon checks for addr type
    external_switch = 1 if 'external' in vis_filter else 0
    internal_switch = 2 if 'internal' in vis_filter else 0
    multi_switch = 3 if 'multi' in vis_filter else 0
    int_sus_switch = 4 if 'internal_suspicious' in vis_filter else 0
    ext_sus_switch = 5 if 'external_suspicious' in vis_filter else 0
    vis_switches = [external_switch, internal_switch, multi_switch, int_sus_switch, ext_sus_switch]  # 4 for alerts (ALWAYS SHOW FOR NOW)

    tcp_switch = 'TCP' if 'tcp' in proto_filter else '0'  # in str since ip_proto field is str
    udp_switch = 'UDP' if 'udp' in proto_filter else '0'
    proto_switches = [tcp_switch, udp_switch]  # TODO: TCP/UDP switches from checkbox to be implemented
    if interface_dropdown is not None:
        active_int = interface_dropdown

    global visdcc_display_dict
    if live_check or n_intervals == 0:  # init build or update with live flows
        visdcc_display_dict['internal'] = csv_to_flow_dict(micro_int_files['internal'])
        visdcc_display_dict['external'] = csv_to_flow_dict(micro_int_files['external'])
        visdcc_display_dict['tap'] = csv_to_flow_dict(micro_int_files['tap'])


    # TODO: Change from full rebuild to something more efficient
    for key in visdcc_display_dict[active_int].keys():  # edges
        if float(visdcc_display_dict[active_int][key].ip_pkt_tot_num) >= flow_slider:  # protect against scan handshakes TODO: MAKE THIS BETTER LATER
            IPandPort = key.split(" ")

            srcIPandPort = IPandPort[0].split(":")
            srcIP = srcIPandPort[0]
            srcPort = srcIPandPort[1]

            destIPandPort = IPandPort[1].split(":")
            destIP = destIPandPort[0]
            destPort = destIPandPort[1]

            srcIPs.append(srcIP)
            destIPs.append(destIP)
            destIP_label, destIP_type = get_anonymized_label(destIP)
            srcIP_label, srcIP_type = get_anonymized_label(srcIP)  # TODO: CLEAN UP AND REMOVE REDUNDANT

            # Add IP check for home/multicast -> if not in either, anonymize. Color depending on both checks
            width1 = float(visdcc_display_dict[active_int][key].ip_pkt_tot_num)
            width = int(math.log((int(width1//10)*10)+1, 10)) + 1
            new_edge = {
                'id': IPandPort[0] + "__" + IPandPort[1],
                'from': srcIP,
                'to': destIP,
                'label': '{}'.format(destPort),
                'width':  width,
                'title':
                    "flow: {}<br>protocol: {}<br>number of packets: {}"
                    "<br>number of bytes: {}<br>duration: {}<br>Label: {}".format(
                    '{}:{} -> {}:{}'.format(srcIP_label, srcPort, destIP_label, destPort),
                    visdcc_display_dict[active_int][key].ip_proto,
                    visdcc_display_dict[active_int][key].ip_pkt_tot_num,
                    visdcc_display_dict[active_int][key].ip_pkt_tot_len,
                    visdcc_display_dict[active_int][key].ip_all_flow_duration,
                    visdcc_display_dict[active_int][key].flow_alert)
            }
            if new_edge not in edges:
                if srcIP_type in vis_switches or destIP_type in vis_switches:
                    if visdcc_display_dict[active_int][key].ip_proto in proto_switches:
                        edges.append(new_edge)

    #search for potential scans by checking for edges with matching to and from IPs
    #scans = {}
    #focus on one edge
    for i in range(len(edges)):
        matches = 0
        #loop through the other edges
        for edge in edges:
            #increment matches if both the to and from IPs match
            if(edges[i]["from"] == edge["from"] and edges[i]["to"] == edge["to"]) or (edges[i]["from"] == edge["to"] and edges[i]["to"] == edge["from"]) and edges[i] != edge:
                #print("Scan match incremented")
                matches += 1
        #if the required amount of matches is reached, add the to and from IPs as a potential scan 
        if(matches > 1): #arbitrary threshold
            #print("Scan found") 
            scans_dict[edges[i]["from"]] = edges[i]["to"]
    #print("Scans: " + str(scans))

    #search for potential sweeps within the edges
    #sweeps = {}
    for i in range(len(edges)):
        matches = 0
        #get the dest port by spliting the edge id
        cur_dest = edges[i]["id"].split("__")[1].split(":")[1]
        for edge in edges:
            edge_dest = edge["id"].split("__")[1].split(":")[1]
            #if the from IPs and dest ports match, it is a potential scan
            if(edges[i]["from"] == edge["from"] or edges[i]["to"] == edge["to"] or edges[i]["to"] == edge["from"]) and cur_dest == edge_dest and edges[i] != edge:
                matches += 1
        if(matches > 1):
            sweeps_dict[edges[i]["from"]] = cur_dest
    #print("Sweeps: " + str(sweeps))
    
    
    ip_all = set(srcIPs + destIPs)

    for ip in ip_all:  # nodes
        ip_label, ip_type = get_anonymized_label(ip)
        num_malicious = 0
        num_udp = 0
        num_tcp = 0
        mal_alerts = {}
        mal_alert_label = ""
        for key in visdcc_display_dict[active_int].keys():  # checking for if node has any malicious flows

            # protocol filtering for each node based on flow protos
            if ip + ':' in key:
                if visdcc_display_dict[active_int][key].ip_proto == 'UDP':
                    num_udp += 1
                elif visdcc_display_dict[active_int][key].ip_proto == 'TCP':
                    num_tcp += 1

            # colon to prevent partial match on last digit i.e 4 and 46
            if ip + ':' in key and ip not in multi_net and ip not in broad_net and ip not in broad_inner and int(visdcc_display_dict[active_int][key].label) == 1:
                num_malicious += 1

                # adding alert type to dict for printing in node
                if visdcc_display_dict[active_int][key].flow_alert not in mal_alerts.keys():
                    mal_alerts[visdcc_display_dict[active_int][key].flow_alert] = 1
                else:
                    mal_alerts[visdcc_display_dict[active_int][key].flow_alert] += 1

                # converting type for coloring/filtering for malicious nodes
                if ip in home_net:
                    ip_type = 4
                else:
                    ip_type = 5

        if len(mal_alerts.keys()) > 0:
            mal_alert_label += 'Alerts:'
        for key in mal_alerts.keys():  # converting from dict to str
            mal_alert_label += "<br>{}: {}".format(key, mal_alerts[key])

        new_node = {
            'id': ip,
            'label': ip_label,
            'shape': 'dot', 'size': 5, 'color': micro_node_color_code[ip_type],

            'title': "{}<br>number of flows: {}<br>malicious flows: {}<br>{}".format(ip_label, len(re.findall(ip + ':', ''.join(
                list(visdcc_display_dict[active_int].keys())))), num_malicious, mal_alert_label)}

        # ip filtering of nodes
        if new_node not in nodes and ip_type in vis_switches:
            # protocol filtering of nodes
            if (num_udp > 0 and 'UDP' in proto_switches) or (num_tcp > 0 and 'TCP' in proto_switches):
                if new_node['id'] in scans_dict and new_node['id'] in sweeps_dict:
                    new_node['color'] = 'brown'
                    scanNodes.append(new_node)
                    sweepNodes.append(new_node)
                    continue
                #if the node is scanning other nodes, display it
                elif new_node['id'] in scans_dict.keys():
                    new_node['color'] = 'blue'
                    nodes.append(new_node)
                    #scanNodes.append(new_node)
                    continue
                #if the node is being scanned, hide it
                elif new_node['id'] in scans_dict.values():
                    scanNodes.append(new_node)
                    continue
                elif new_node['id'] in sweeps_dict:
                    new_node['color'] = 'pink'
                    sweepNodes.append(new_node)
                    continue
                nodes.append(new_node)

    data = {'nodes': nodes, 'edges': edges}
    #current data is a global dictionary to be used in the scans/sweeps callback function
    current_data['nodes'] = nodes
    current_data['edges'] = edges

    print("Number of nodes to display: " + str(len(data['nodes'])))


    active_flows = "Active flows: {}".format(len(visdcc_display_dict[active_int].keys()))

    alerts = {}  # TODO: RETURN ACTIVE ALERTS TO BE DISPLAYED SOMEWHERE
    for key in visdcc_display_dict[active_int].keys():
        if int(visdcc_display_dict[active_int][key].label) == 1 and visdcc_display_dict[active_int][key].flow_alert not in alerts.keys():
            alerts[visdcc_display_dict[active_int][key].flow_alert] = 0
        elif int(visdcc_display_dict[active_int][key].label) == 1:
            alerts[visdcc_display_dict[active_int][key].flow_alert] += 1

    return current_data, active_flows


#input: 
#output: net, data
@dash_app_micro.callback(
    #Output(component_id='net', component_property='data'),
    Output(component_id='net', component_property='selection'),
    Input('net', 'data'),
    Input(component_id='net', component_property='selection'),
    prevent_initial_call=True
)
def display_sweeps_and_scans(net_data, clicked_node):
    #time.sleep(5)
    print("running click function")
    #print("Current net data: " + str(net_data))
    print("nodes clicked: " + str(clicked_node))
    total_data = {'nodes': [], 'edges': []}
    #print(current_data['nodes'])
    if(len(clicked_node['nodes']) > 0):
        print("you clicked a node")
        print("Number of clicked nodes: " + str(len(clicked_node['nodes'])))
        
        #print(clicked_node['nodes'][0])
        for node in clicked_node['nodes']:
            print(node)
        return clicked_node #, net_data

        #print("Scans: " + str(scans_dict))
        #print("Sweeps: " + str(sweeps_dict))
        #total_data['nodes'] = current_data['nodes'] + scanNodes + sweepNodes
    else:
        print("Preventing update")
        raise PreventUpdate
        #return net_data, clicked_node
    #final_data = {'nodes': total_data['nodes'], 'edges': current_data['edges']}
    #return clicked_node
    #return current_data, clicked_node


def create_dash_macro(flask_app):
    dash_app = Dash(server=flask_app, name='dashboard', url_base_pathname='/dash/')
    dash_app.layout = html.Div(
        html.Div([
            dcc.Graph(
                id='main_graph_line',
                figure=px.line(df, x='date', y=df.columns.values.tolist()[1:6],
                               title='H-CyTE Alerts')  # TODO: FIX FROM HARD CODE COL CALL
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
            html.Div([html.Div(html.B('Total Alerts:'), style={'margin-right': '15px', 'display': 'inline-block'}),
                      html.Div(id='total_value', style={'display': 'inline-block'}),
                      html.Div(dcc.Dropdown(
                          df_flows_drop,
                          'num_flows',
                          id='yaxis-column'), style={'width': '48%', 'float': 'right', 'display': 'inline-block'})
                      ], style={'margin-bottom': '20px'}),
            html.Div([html.Div(dcc.Graph(id='secondary_graph_pie'),
                               style={'width': '50%', 'display': 'inline-block'}),
                      html.Div(dcc.Graph(id='secondary_graph_flow'),
                               style={'width': '50%', 'display': 'inline-block'})]),

        ])

    )
    return dash_app


dash_app_macro = create_dash_macro(flask_app=app)
dash_app_macro.scripts.config.serve_locally = True

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


@dash_app_macro.callback(
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
                  hover_name='date', hover_data=df1.columns.tolist(), x='date', y=y_name).update_xaxes(
        rangeslider_visible=True)
    return fig


@dash_app_macro.callback(
    Output(component_id='total_value', component_property='children'),
    Output(component_id='secondary_graph_pie', component_property='figure'),
    Input(component_id='main_graph_line', component_property='hoverData'),
    Input(component_id='main_graph_line', component_property='clickData'))
def displayHoverDataGraph(hoverData=None, clickData=None):
    if hoverData is not None:
        date1 = hoverData['points'][0]['x']
        curve = curve_nums[hoverData['points'][0]['curveNumber']]

    elif clickData is not None:
        date1 = clickData['points'][0]['x']
        curve = curve_nums[clickData['points'][0]['curveNumber']]

    else:
        date1 = str(dt.date.today() - dt.timedelta(days=1))
        # TODO: CHANGE TO dt.date.today() - timedelta(days=1) when day to day updating is implemented
        curve = curve_nums[1]

    df1 = df.loc[df['date'] == date1]  # gets row from selected day, gets rid of rest
    if curve != 'all_alerts':
        curve_regex = '^{}_'.format(curve.split('_')[0])
        # If not all, can apply strict regex based on first word in each column (MAKE SURE TO INCLUDE). Otherwise, no need to filter
        curve_columns = df1.filter(regex=curve_regex,
                                   axis=1).columns.tolist()  # regex for first word as id as enumerated in curve_nums
        total = df1[curve_columns[0]]  # Will be first one since line columns are first in df
        specific_alerts = curve_columns[1:]  # may not add up until all alerts are enumerated (PAIN IN THE ASS)
    else:
        # all alerts curve selected
        curve_columns = df1.drop(columns=['date'], axis=1).drop(
            columns=df1.filter(regex='^scan_', axis=1).columns.tolist(), axis=1)
        # Remove date and scan (not relevant for snort all alerts)
        total = curve_columns['all_alerts']

        sub_col_list = list(curve_nums.values())
        sub_col_list.remove('scan_num')  # Need to remove since key error (scan_num dropped by filter)
        specific_alerts = curve_columns.drop(columns=sub_col_list,
                                             axis=1).columns.tolist()  # may not add up until all alerts are enumerated (PAIN IN THE ASS)
        # Drop generalized columns (used in big graph)

    df_filtered = df1[specific_alerts]
    df_filt_dict = df_filtered.to_dict('records')[0]

    df_no_zero_dict = {}
    df_filtered = df.loc[:, (df != 0).any(axis=0)]
    # drop 0 columns and update dict accordigly (didnt work if updating df then doing to_dict
    for key in df_filt_dict.keys():
        if df_filt_dict[key] > 0:
            df_no_zero_dict[key] = df_filt_dict[key]

    fig = px.pie(data_frame=df_filtered, title="{} Expanded: {}".format(curve, date1), names=df_no_zero_dict.keys(),
                 values=df_no_zero_dict.values()).update_traces(hoverinfo='label+percent')
    return total, fig


@app.route('/', strict_slashes=False, methods=["GET"])
@app.route('/macro', strict_slashes=False, methods=["GET"])
def macro():
    dash_macro = dash_app_macro.index()
    return render_template('macro.html', dash_html=dash_macro)


@app.route('/micro', strict_slashes=False)
def micro():
    dash_micro = dash_app_micro.index()
    return render_template('micro.html', vis_html=dash_micro)


@app.route('/about', strict_slashes=False)
def about():
    return render_template('about.html')


@app.route('/contact', strict_slashes=False, methods=["GET", "POST"])
def contact():
    form = forms.EmailForm()
    if request.method == 'POST' and form.validate_on_submit():
        interests = request.form.getlist('interest')
        data_contact = {
            'date': dt.date.today(),
            'firstname': request.form.get('first_name'),
            'lastname': request.form.get('last_name'),
            'email': request.form.get('email'),
            'org': request.form.get('org'),
            'more_info': 1 if 'More Information' in interests else 0,
            'data_sharing': 1 if 'Data Sharing' in interests else 0,
            'collaboration': 1 if 'Collaboration' in interests else 0,
            'contacted': 0
        }
        df_contact = pd.DataFrame(data_contact, index=[0])
        df_contact.to_csv('static/contact_list.csv', mode='a', index=False, header=False)
        # EMAIL HERE

        return redirect(url_for('submit'))
    return render_template('contact.html', form=form)


@app.route('/submit', methods=["GET"])
def submit():
    return render_template('submit.html')

