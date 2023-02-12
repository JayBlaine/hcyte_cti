import datetime as dt
import os
import threading
import time
import re
import copy

from flask import Flask, render_template, redirect, url_for, request
import pandas as pd
import plotly.express as px
from dash import Dash, html, dcc, Output, Input
import visdcc
from netaddr import IPNetwork

from webApp import forms
from webApp import flow_tracker
from webApp import t_flows

app = Flask(__name__)
app.config['SESSION_COOKIE_SAMESITE'] = "Secure"
app.config['SECRET_KEY'] = 'b6821eaa9fce8996030370c7831fd2cc2d7a509254551bdb'

app.config['RECAPTCHA_USE_SSL'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = '6Ld81k4kAAAAAHaEuoxKtg7N2QE11yjP3ySy8X-U'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6Ld81k4kAAAAANDMNw2lbt5hzjXg71XbErsN37S3'
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)
# flow_sniffer.sniffer.start()


def follow(file):
    """
    Behaves like tail -f: follows file and returns new lines as they're appended
    :param file: followed file
    :return: yields lines as they're appended, continues execution.
    """
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line


def alert_follow():
    alert_file = open('/mnt/captures/snort_internal/alert', "r")
    alert_lines = follow(alert_file)

    for line in alert_lines:
        line_list = line.split()
        src = line_list[-3:][0]
        dst = line_list[-1:][0]
        try:
            flow_sniffer.flows["{} {}".format(src, dst)].label = 1
            flow_sniffer.flows["{} {}".format(src, dst)].flow_alert = re.split(r'\[\*\*]', line)[1]
        except KeyError:
            try:
                flow_sniffer.flows["{} {}".format(dst, src)].label = 1
                flow_sniffer.flows["{} {}".format(src, dst)].flow_alert = re.split(r'\[\*\*]', line)[1]
            except KeyError:
                # Key error: Some snort rules (port sweep) don'flow_sniffer have port number -> can'flow_sniffer find reliably
                continue


# reading from /mnt/captures/snort_internal/alert
flow_sniffer = flow_tracker.FlowTracker(iface='eno1', timeout=60)
follow_thread = threading.Thread(target=alert_follow, name="alert_follower")
visdcc_display_dict = {}
home_net = IPNetwork("192.168.50.0/24")
broadcast_net = IPNetwork("224.0.0.0/4")


#app = build_app()

#df = pd.read_csv('static/website_data.csv')  # TODO: CHANGE TO STATIC /var/www/webApp/webApp/static
#df_flows = pd.read_csv('static/website_flow_data.csv')
df = pd.read_csv('/var/www/webApp/webApp/static/website_data.csv')  # TODO: CHANGE TO STATIC /var/www/webApp/webApp/static
df_flows = pd.read_csv('/var/www/webApp/webApp/static/website_flow_data.csv')

df_flows_drop = df_flows.filter(regex='^all_', axis=1).columns.tolist()
df_flows_drop = [i[4:] for i in df_flows_drop]  # remove 'all_' to make use for other protocol filters



# TODO: REGENERATE WHEN LIVE HOSTING  https://www.google.com/recaptcha/admin/create



def get_anonymized_label(addr: str):
    addr_type = 1  # 1 = outside home sub, 2 = insdie home/net, 3 = broad/multicast
    if addr in home_net:
        addr_type = 2
    elif addr in broadcast_net:
        addr_type = 3

    if addr not in home_net and addr not in broadcast_net:
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
    4: 'red',
    5: 'red'
}


def create_dash_micro(flask_app):
    external_stylesheets = ['https://cdnjs.cloudflare.com/ajax/libs/vis/4.20.1/vis.min.css']
    dash_app1 = Dash(server=flask_app, name='dashboard1', url_base_pathname='/dash1/',
                     external_stylesheets=external_stylesheets)

    dash_app1.layout = html.Div([html.Div(dcc.Checklist(id='live_check', options=[{'label': 'Live Feed', 'value': 'live'}],
                                                        value=['live'])),
                                 html.Div(dcc.Checklist(id='vis_filter', options=
                                 [{'label': 'Internal', 'value': 'internal'},
                                  {'label': 'External', 'value': 'external'},
                                  {'label': 'Multi/Broadcast', 'value': 'multi'},
                                  {'label': 'Internal Suspicious Nodes', 'value': 'internal_suspicious'},
                                  {'label': 'External Suspicious Nodes', 'value': 'external_suspicious'}],
                                                        value=['internal', 'external', 'multi', 'internal_suspicious', 'external_suspicious'])),
                                 visdcc.Network(id='net',
                                                options=dict(height='600px', width='100%')),

                                 dcc.Interval(
                                     id='interval_component',
                                     interval=5 * 1000,  # in milliseconds
                                     n_intervals=0
                                 ), html.Div(id='hidden_div', style={'display': 'none'})])

    return dash_app1


dash_app_micro = create_dash_micro(flask_app=app)
dash_app_micro.scripts.config.serve_locally = True


@dash_app_micro.callback(
    Output(component_id='net', component_property='data'),
    Input(component_id='interval_component', component_property='n_intervals'),
    Input(component_id='live_check', component_property='value'),
    Input(component_id='vis_filter', component_property='value')
)
def build_visdcc(n_intervals=None, live_check=None, vis_filter=None):
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
    global visdcc_display_dict
    if live_check or n_intervals == 0:  # init build or update with live flows
        visdcc_display_dict = copy.deepcopy(t_flows.test_flows)  # change to flow_sniffer.flows dict when live

    # TODO: Change from full rebuild to something more efficient
    for key in visdcc_display_dict.keys():  # edges
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


        """
        if visdcc_display_dict[key].label == 1:  # set type to correct maliciousness
            if srcIP in home_net:
                srcIP_type = 4
            else:
                srcIP_type = 5
            if destIP in home_net:
                destIP_type = 4
            else:
                destIP_type = 5
        """


        # Add IP check for home/multicast -> if not in either, anonymize. Color depending on both checks
        new_edge = {
            'id': IPandPort[0] + "__" + IPandPort[1],
            'from': srcIP,
            'to': destIP,
            'label': '{}'.format(destPort),
            'width': 2,
            'title': "flow: {}<br>number of packets: {}<br>number of bytes: {}<br>duration: {}<br>Label: {}".format(
                '{}:{} -> {}:{}'.format(srcIP_label, srcPort, destIP_label, destPort),
                visdcc_display_dict[key].ip_pkt_tot_num,
                visdcc_display_dict[key].ip_pkt_tot_len,
                visdcc_display_dict[key].ip_all_flow_duration,
                visdcc_display_dict[key].flow_alert)
        }
        if new_edge not in edges:
            if srcIP_type in vis_switches or destIP_type in vis_switches:
                edges.append(new_edge)

    ip_all = set(srcIPs + destIPs)

    for ip in ip_all:  # nodes
        ip_label, ip_type = get_anonymized_label(ip)
        num_malicious = 0
        for key in visdcc_display_dict.keys():  # checking for if node has any malicious flows
            if ip not in broadcast_net and visdcc_display_dict[key].label == 1 and ip+':' in key:
                # colon to prevent partial match on last digit i.e 4 and 46
                num_malicious += 1
                if ip in home_net:
                    ip_type = 4
                else:
                    ip_type = 5
        new_node = {
            'id': ip,
            'label': ip_label,
            'shape': 'dot', 'size': 10, 'color': micro_node_color_code[ip_type],

            'title': "{}<br>number of flows: {}<br>malicious flows: {}".format(ip, len(re.findall(ip + ':', ''.join(
                list(visdcc_display_dict.keys())))), num_malicious)}  # replace with live capturer
        if new_node not in nodes:
            if ip_type in vis_switches:
                nodes.append(new_node)

    data = {'nodes': nodes, 'edges': edges}
    return data


def create_dash_macro(flask_app):
    dash_app = Dash(server=flask_app, name='dashboard', url_base_pathname='/dash/')
    dash_app.layout = html.Div(
        html.Div([
            dcc.Graph(
                id='main_graph_line',
                figure=px.line(df, x='date', y=df.columns.values.tolist()[1:6],
                               title='H-CyTE Stuff')  # TODO: FIX FROM HARD CODE COL CALL
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
        curve_columns = df1.filter(regex=curve_regex,
                                   axis=1).columns.tolist()  # regex for first word as id as enumerated in curve_nums
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

