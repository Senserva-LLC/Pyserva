# Load Python libraries that will be used in this notebook
from azure.common.client_factory import get_client_from_cli_profile
from azure.common.credentials import get_azure_cli_credentials
from azure.loganalytics.models import QueryBody
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.loganalytics import LogAnalyticsDataClient

# Processing Helpers
import pandas as pd
import json
import ipywidgets
from IPython.display import display, HTML, Markdown
import json
import networkx as nx
import csv
import requests

#Bokeh Visualization Helpers
import bokeh
import bokeh.io
from bokeh.io import output_notebook, show, save
from bokeh.models import Range1d, Circle, ColumnDataSource, MultiLine
from bokeh.plotting import figure, from_networkx
from bokeh.palettes import Spectral11
from bokeh.resources import INLINE
bokeh.io.output_notebook(INLINE)

# Functions that will be used in this notebook
def read_config_values(file_path):
    '''This loads pre-generated parameters for Sentinel Workspace. This should be provided to your workspace via a config.json file'''

    with open(file_path) as json_file:
        if json_file:
            json_config = json.load(json_file)
            return (json_config["tenant_id"],
                    json_config["subscription_id"],
                    json_config["resource_group"],
                    json_config["workspace_id"],
                    json_config["workspace_name"],
                    json_config["user_alias"],
                    json_config["user_object_id"])
    return None

def has_valid_token():
    '''Check to see if there is a valid AAD token, otherwise throw exception'''

    try:
        credentials, sub_id = get_azure_cli_credentials()
        creds = credentials._get_cred(resource=None)
        token = creds._token_retriever()[2]
        print("Successfully signed in.")
        return True
    except Exception as ex:
        if "Please run 'az login' to setup account" in str(ex):
            print(str(ex))
            return False
        elif "AADSTS70043: The refresh token has expired" in str(ex):
            message = "**The refresh token has expired. <br> Please continue your login process. Then: <br> 1. If you plan to run multiple notebooks on the same compute instance today, you may restart the compute instance by clicking 'Compute' on left menu, then select the instance, clicking 'Restart'; <br> 2. Otherwise, you may just restart the kernel from top menu. <br> Finally, close and re-load the notebook, then re-run cells one by one from the top.**"
            display(Markdown(message))
            return False
    except:
        print("Please restart the kernel, and run 'az login'.")
        return False

def process_result(result):
    '''This function processes data returned from Azure LogAnalyticsDataClient, it returns pandas DataFrame'''

    json_result = result.as_dict()
    cols = pd.json_normalize(json_result['tables'][0], 'columns')
    final_result = pd.json_normalize(json_result['tables'][0], 'rows')
    if final_result.shape[0] != 0:
        final_result.columns = cols.name

    return final_result
    
def SenservaPermissionQuery(tableName):
    '''Query for finding relationships from the Senserva Scanner results. 
    If you have set up multiple workspaces, provide a Sentinel alias to query both functions'''

    where_clause = "{0} | where TimeGenerated > ago(7d)| where (ControlName_s == 'ServicePrincipalPermissionGrantTenant' or ControlName_s == 'ApplicationPermissionGrantTenant' or ControlName_s == 'ServicePrincipalMembership' or ControlName_s == 'UserMembers' or ControlName_s =='UserOwners' or ControlName_s =='GroupMembers') | extend values =tostring(parse_json(Value_s)) | extend JSON = todynamic(values) | order by TimeGenerated desc"
    return where_clause.format(tableName)

def PluckDataFromQueryResults(query_result, names_list, csvFileWriter):
    '''Given Senserva query results, pick out the data we want. 
    The data will be written as tuples to a given CSV file writer object. 
    The format of each line of the file will be [Source,Target,relationship,weight].
    All unique objects will be colelcted and returned as a dropdown menu, to allow for user selected filtering'''

    # Set up some values
    name_user = 'User'
    name_disabled_user = 'DisabledUser'
    name_group = 'Group'
    name_role = 'Role'
    name_all_users = 'All Users'
    name_unknown = 'Unknown'

    weight_user = '1'
    weight_disabled_user = '8'
    weight_group = '4'
    weight_role = '5'
    weight_application = '6'
    weight_all_users = '3'
    weight_unknown = '10'

    memberRelationship = 'Member'
    indirectMemberRelationship = 'Indirect Member'
    ownerRelationship = 'Owner'
    permissionRelationship = 'Permission to Use'

    # Loop through our results and process the relationships
    try:
        for index,value in query_result.JSON.items():
            JSONItems = json.loads(value)
            targetName = "Unknown"
            userList = []
            disabledUserList = []
            unknownObjectList = []
            directGroupList = []
            directRoleList = []
            directApplicationList = []
            directServicePrincipalList = []
            directUnknownList = []
            indirectGroupList = []
            indirectRoleList = []
            indirectUnknownList = []
            edges = []
            for x in JSONItems:
                if 'Tag' in x:
                    # Find our target that we are working with
                    if(x['Tag'] == "ApplicationName" or x['Tag'] =="ServicePrincipalName" or x['Tag'] =="UserName"):
                        targetName = x['Val']
                        names_list.append(targetName)
                    
                    
                    # We have a Service Principal that has been granted consent for the tenant by a tenant admin
                    if(x['Tag'] == "ServicePrincipalTenantPermissionGrantList"):
                        edges.append([targetName,name_all_users,weight_application,weight_all_users, permissionRelationship,MapRisk(query_result.Risk_d[index])])

                    # We have a Service Principal that has been granted consent for a particular user
                    if(x['Tag'] == "ServicePrincipalUserPermissionGrantList"):
                        for nameValuePair in x['Val']:
                            userList, unknownObjectList, edges = ParseQueryResultHelper(nameValuePair, userList, unknownObjectList, edges, 'Item1', 'Item2', targetName, weight_application, weight_user, weight_unknown, permissionRelationship, query_result.Risk_d[index])
                    
                    # We have a Service Principal that has been granted consent for a particular disabled user
                    if(x['Tag'] == "ServicePrincipalDisabledUserPermissionGrantList"):
                        for nameValuePair in x['Val']:
                            disabledUserList, unknownObjectList, edges = ParseQueryResultHelper(nameValuePair, disabledUserList, directUnknownList, edges, 'Item1', 'Item2', targetName, weight_application, weight_disabled_user, weight_unknown, permissionRelationship, query_result.Risk_d[index])

                    # We have a Service Principal that has been granted consent for an AAD Object that is not recognized
                    if(x['Tag'] == "ServicePrincipalUnknownObjectPermissionGrantList"):
                        for nameValuePair in x['Val']:
                            unknownObjectList, unknownObjectList, edges = ParseQueryResultHelper(nameValuePair, unknownObjectList, unknownObjectList, edges, 'Item1', 'Item2', targetName, weight_application, weight_unknown, weight_unknown, permissionRelationship, query_result.Risk_d[index])

                    # We have a Service Principal that is directly assigned as a member of an AAD Group
                    if(x['Tag'] == "ServicePrincipalDirectGroupMember"):
                        for nameValuePair in x['Val']:
                            directGroupList, directUnknownList, edges = ParseQueryResultHelper(nameValuePair, directGroupList, directUnknownList, edges, 'Name', 'Id', targetName, weight_application, weight_group, weight_unknown, memberRelationship, query_result.Risk_d[index])

                    # We have a Service Principal that is directly assigned an AAD role membership
                    if(x['Tag'] == "ServicePrincipalDirectRoleMember"):
                        for nameValuePair in x['Val']:
                            directRoleList, directUnknownList, edges = ParseQueryResultHelper(nameValuePair, directRoleList, directUnknownList, edges, 'Name', 'Id', targetName, weight_application, weight_role, weight_unknown, memberRelationship, query_result.Risk_d[index])

                    # We have a Service Principal that is directly assigned membership to an unknown AAD object
                    if(x['Tag'] == "ServicePrincipalDirectUnknownMember"):
                        for nameValuePair in x['Val']:
                            directUnknownList, directUnknownList, edges = ParseQueryResultHelper(nameValuePair, directUnknownList, directUnknownList, edges, 'Name', 'Id', targetName, weight_application, weight_unknown, weight_unknown, memberRelationship, query_result.Risk_d[index])

                    # We have a Service Principal that has indirect membership to a group e.g. SP is member of Group A, Group A is a member of Group B
                    if(x['Tag'] == "ServicePrincipalIndirectGroupMember"):
                        for nameValuePair in x['Val']:
                            indirectGroupList, indirectUnknownList, edges = ParseQueryResultHelper(nameValuePair, indirectGroupList, indirectUnknownList, edges, 'Name', 'Id', targetName, weight_application, weight_group, weight_unknown, indirectMemberRelationship, query_result.Risk_d[index])

                    # We have a Service Principal that has indirect role membership e.g. SP is member of Group A, Group A is assigned Role B
                    if(x['Tag'] == "ServicePrincipalIndirectRoleMember"):
                        for nameValuePair in x['Val']:
                            indirectRoleList, indirectUnknownList, edges = ParseQueryResultHelper(nameValuePair, indirectRoleList, indirectUnknownList, edges, 'Name', 'Id', targetName, weight_application, weight_role, weight_unknown, indirectMemberRelationship, query_result.Risk_d[index])

                    # We have a Service Principal that has indirect membership to an unknown AAD object
                    if(x['Tag'] == "ServicePrincipalIndirectUnknownMember"):
                        for nameValuePair in x['Val']:
                            indirectUnknownList, indirectUnknownList, edges = ParseQueryResultHelper(nameValuePair, indirectUnknownList, indirectUnknownList, edges, 'Name', 'Id', targetName, weight_application, weight_unknown, weight_unknown, indirectMemberRelationship, query_result.Risk_d[index])

                    # We have a user that is a member of an AAD Group
                    if(x['Tag'] == "GroupMemberUser"):
                        userList.append(targetName)
                        for nameValuePair in x['Val']:
                            directGroupList, directUnknownList, edges = ParseQueryResultHelper(nameValuePair, directGroupList, directUnknownList, edges, 'Name', 'Id', targetName, weight_user, weight_group, weight_unknown, memberRelationship, query_result.Risk_d[index])

                    # We have a user that is a assigned a role membership
                    if(x['Tag'] == "RoleMemberUser"):
                        userList.append(targetName)
                        for nameValuePair in x['Val']:
                            directRoleList, directUnknownList, edges = ParseQueryResultHelper(nameValuePair, directRoleList, directUnknownList, edges, 'Name', 'Id', targetName, weight_user, weight_role, weight_unknown, memberRelationship, query_result.Risk_d[index])

                    # We have a group that is a assigned a group membership
                    if(x['Tag'] == "GroupMemberGroup"):
                        directGroupList.append(targetName)
                        for nameValuePair in x['Val']:
                            directGroupList, directUnknownList, edges = ParseQueryResultHelper(nameValuePair, directGroupList, directUnknownList, edges, 'Name', 'Id', targetName, weight_group, weight_group, weight_unknown, memberRelationship, query_result.Risk_d[index])

                    # We have a group that is a assigned a role membership
                    if(x['Tag'] == "GroupMemberRole"):
                        directGroupList.append(targetName)
                        for nameValuePair in x['Val']:
                            directRoleList, directUnknownList, edges = ParseQueryResultHelper(nameValuePair, directRoleList, directUnknownList, edges, 'Name', 'Id', targetName, weight_group, weight_role, weight_unknown, memberRelationship, query_result.Risk_d[index])

                    # We have a user that is a assigned a group ownership
                    if(x['Tag'] == "GroupOwners"):
                        userList.append(targetName)
                        for nameValuePair in x['Val']:
                            directGroupList, directUnknownList, edges = ParseQueryResultHelper(nameValuePair, directGroupList, directUnknownList, edges, 'Name', 'Id', targetName, weight_group, weight_user, weight_unknown, ownerRelationship, query_result.Risk_d[index])

                    # We have a user that is a assigned an application ownership
                    if(x['Tag'] == "ApplicationOwner"):
                        userList.append(targetName)
                        for nameValuePair in x['Val']:
                            directApplicationList, directUnknownList, edges = ParseQueryResultHelper(nameValuePair, directApplicationList, directUnknownList, edges, 'Name', 'Id', targetName, weight_application, weight_user, weight_unknown, ownerRelationship, query_result.Risk_d[index])

                    # We have a user that is a assigned a service principal ownership
                    if(x['Tag'] == "ServicePrincipalOwner"):
                        userList.append(targetName)
                        for nameValuePair in x['Val']:
                            directServicePrincipalList, directUnknownList, edges = ParseQueryResultHelper(nameValuePair, directServicePrincipalList, directUnknownList, edges, 'Name', 'Id', targetName, weight_application, weight_user, weight_unknown, ownerRelationship, query_result.Risk_d[index])

                else:
                    continue
            for user in userList:   
                names_list.append(user)
            for disabledUser in disabledUserList:
                names_list.append(disabledUser)
            for unknownObject in unknownObjectList:
                names_list.append(unknownObject)
            for directGroup in directGroupList:
                names_list.append(directGroup)
            for directRole in directRoleList:
                names_list.append(directRole)
            for directApplication in directApplicationList:
                names_list.append(directApplication)
            for directServicePrincipal in directServicePrincipalList:
                names_list.append(directServicePrincipal)
            for directUnknown in directUnknownList:
                names_list.append(directUnknown)
            for indirectGroup in indirectGroupList:
                names_list.append(indirectGroup)
            for indirectRole in indirectRoleList:
                names_list.append(indirectRole)
            for indirectUnknown in indirectUnknownList:
                names_list.append(indirectUnknown)

            # Write our edges to the file for later use
            for edge in edges:
                csvFileWriter.writerow(edge)
                
                
        # Take our list of objects and make a dropdown list to use for filtering
        names = sorted(set(names_list))
        name_dropdown = ipywidgets.Dropdown(options=names, description='Objects:')
        display(name_dropdown)

        return name_dropdown

    except AttributeError:
        print('No data found from the query')

    return

def ParseQueryResultHelper(nameValuePair, foundList, defaultList, edgesList, primaryKey, backupKey, sourceName, weightSource, weightFound, weightNotFound, relationship, risk):
    '''Helper to parse through query results'''

    if(primaryKey in nameValuePair.keys()):
        foundList.append(nameValuePair[primaryKey])
        edgesList.append([sourceName,nameValuePair[primaryKey],weightSource,weightFound, relationship, MapRisk(risk)])
    elif(backupKey in nameValuePair.keys()):
        foundList.append(nameValuePair[backupKey])
        edgesList.append([sourceName,nameValuePair[backupKey],weightSource,weightFound, relationship, MapRisk(risk)])
    else:
        defaultList.append(nameValuePair)
        edgesList.append([sourceName,nameValuePair,weightSource,weightNotFound, relationship, MapRisk(risk)])
    
    return (foundList, defaultList, edgesList)

def MapRisk(risk):
    '''Map the Risk Value to a Name'''

    result = ''
    if(risk == 0):
        result = 'None'
    elif(risk == 1):
        result = 'Very Low'
    elif(risk == 5):
        result = 'Low'
    elif(risk == 10):
        result = 'Medium'
    elif(risk == 20):
        result = 'High'
    elif(risk == 30):
        result = 'Very High'
    elif(risk == 50):
        result = 'Critical'
    else:
        result = 'Unknown'

    return result

def RenderGraphData(file_df):
    '''Given a Pandas data frame from a CSV file, parse the data out, process it for rendering with a Networkx Graph.
    Each line in Data frame is expected to be in form [Source,Target,SourceWeight,TargetWeight,Relationship,Risk]'''

    # Set up the Graph 
    G = nx.Graph
    keys = {}
    values = {}
    modularity_class = {}
    modularity_color = {}
    relationship = {}
    risk = {}

    # Process the passed in data frame and make nodes/edges data for graph
    # Use a data frame because networkx expects a data frame
    G = nx.from_pandas_edgelist(file_df, 'Source','Target', True)
    for index, row in file_df.iterrows():
        # SSame node might appear multiple times, find and use only highest value
        if(row['Source'] in keys):
            keys[row['Source']] = max(int(row['SourceWeight']), int(keys[row['Source']]))
        else:
            keys[row['Source']] = int(row['SourceWeight'])

        if(row['Target'] in keys):
            keys[row['Target']] = max(int(row['TargetWeight']), int(keys[row['Target']]))
        else:
            keys[row['Target']] = int(row['TargetWeight'])

        modularity_class[row['Source']] = keys[row['Source']]
        modularity_color[row['Source']] = Spectral11[keys[row['Target']]]
        modularity_class[row['Target']] = keys[row['Source']]
        modularity_color[row['Target']] = Spectral11[keys[row['Target']]]
        relationship[row['Target']] = row['Relationship']
        risk[row['Target']] = row['Risk']

    degrees = dict(nx.degree(G))
    nx.set_node_attributes(G, degrees, 'degree')

    # Set the node size after we have processed the data
    number_to_adjust_by = 10
    adjusted_node_size = dict([(node, degree+number_to_adjust_by) for node, degree in nx.degree(G)])
    nx.set_node_attributes(G, adjusted_node_size, 'adjusted_node_size')

    # Add modularity class, color, and relationship as attributes from the network above
    nx.set_node_attributes(G, modularity_class, 'modularity_class')
    nx.set_node_attributes(G, modularity_color, 'modularity_color')
    nx.set_node_attributes(G, relationship, 'relationship')
    nx.set_node_attributes(G, risk, 'risk')


    #Choose attributes from G network to size and color by — setting manual size (e.g. 10) or color (e.g. 'skyblue') also allowed
    size_by_this_attribute = 'adjusted_node_size'
    color_by_this_attribute = 'modularity_color'

    #Choose a title!
    title = 'Azure Active Directory Network'

    #Establish which categories will appear when hovering over each node
    HOVER_TOOLTIPS = [
        ("Source", "@index"),
        ("Number of Connections", "@degree"),
        ("Risk", "@risk"),
    ]

    #Create a plot — set dimensions, toolbar, and title
    plot = figure(tooltips = HOVER_TOOLTIPS,
                tools="pan,wheel_zoom,save,reset, tap", active_scroll='wheel_zoom',
                x_range=Range1d(-10.1, 10.1), y_range=Range1d(-10.1, 10.1), title=title)

    # Create a network graph object
    # https://networkx.github.io/documentation/networkx-1.9/reference/generated/networkx.drawing.layout.spring_layout.html
    network_graph = from_networkx(G, nx.spring_layout, scale=10, center=(0, 0))

    #Set node sizes and colors according to node degree (color as category from attribute)
    network_graph.node_renderer.glyph = Circle(size=size_by_this_attribute, fill_color=color_by_this_attribute)

    # Set edge opacity and width
    network_graph.edge_renderer.glyph = MultiLine(line_alpha=0.5, line_width=1)

    # Render the graph
    plot.renderers.append(network_graph)
    show(plot)

    return

def htmlTableParser(list):
    '''Given a list of edge data, parse out the items and format for use in HTML Tabulator Table display'''

    str = ''

    for item in list:
        str += '{Source:"' + item["Source"] + '", Target:"' + item["Target"] + '", relationship:"' + item["Relationship"] + '", risk:"' + item["Risk"] + '", weight:"' + f"{item['TargetWeight']}" + '"},'
    
    return str

def htmlTreeParser(list):
    '''Given a list of edge data, parse out the items and format for use in HTML Tabulator Tree display'''

    str = ''
    dict = {}

    # Load the dictionary with all the values
    for item in list:
        dict.setdefault(item["Source"], []).append((item["Target"], item["Relationship"], item["Risk"], item["TargetWeight"]))
    
    # Once all values found, trim the dictionary to unique values
    for key,value in dict.items():
        dict[key] = set(value)

    # Format all dictionary values for display with HTML Tabulator tree structure
    for key, value in dict.items():
        childrenString = ''
        for item in value:
            childrenString += '{Source:"' + item[0] + '", relationship:"' + item[1] + '", risk:"' + item[2] + '", weight:"' + (f"{item[3]}") + '"},'
        str += '{Source:"' + key + '", _children:[' + childrenString + ']},'

    return str

def filterHelper(name_dropdown, file_df, defaultFilter):
    '''Based on given edge data CSV file and ipywidgets.Dropdown selection, filter the edge data'''

    if(name_dropdown.value != defaultFilter):
        file_df_filtered = file_df[(file_df.Target == name_dropdown.value)]
        file_df_filtered = file_df_filtered.append(file_df[(file_df.Source == name_dropdown.value)])
        return file_df_filtered
    else:
        return file_df

def filterDataFrameAndCreateList(name_dropdown, file_df, defaultFilter):
    '''Create a filtered list from given edge data CSV file and ipywidgets.Dropdown selection'''

    items = []
    file_df_filtered = filterHelper(name_dropdown, file_df, defaultFilter)
    for index, row in file_df_filtered.iterrows():
        items.append(row)
    return items