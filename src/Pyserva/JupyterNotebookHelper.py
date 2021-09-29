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
    # This loads pre-generated parameters for Sentinel Workspace
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
    # Check to see if there is a valid AAD token
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
    # This function processes data returned from Azure LogAnalyticsDataClient, it returns pandas DataFrame
    json_result = result.as_dict()
    cols = pd.json_normalize(json_result['tables'][0], 'columns')
    final_result = pd.json_normalize(json_result['tables'][0], 'rows')
    if final_result.shape[0] != 0:
        final_result.columns = cols.name

    return final_result
    
def SenservaPermissionQuery(tableName):
    # Query for finding relationships from the Senserva Scanner results
    where_clause = "{0} | where TimeGenerated > ago(7d)| where (ControlName_s == 'ServicePrincipalPermissionGrantTenant' or ControlName_s == 'ApplicationPermissionGrantTenant' or ControlName_s == 'ServicePrincipalMembership' or ControlName_s == 'UserMembers' or ControlName_s =='UserOwners' or ControlName_s =='GroupMembers') | extend values =tostring(parse_json(Value_s)) | extend JSON = todynamic(values) | order by TimeGenerated desc"
    return where_clause.format(tableName)

def SenservaLocationQuery(tableName):
    # Query for finding Location data
    where_clause = "{0} | where ControlName_s == 'Locations' | extend values =tostring(parse_json(Value_s)) | extend JSON = todynamic(values) | extend Hash = tostring(JSON[4].Value) | extend Location = tostring(geo_geohash_to_polygon(Hash)) | where Location != ''  | order by TimeGenerated desc"
    return where_clause.format(tableName)

def PluckDataFromQueryResults(query_result, names_list):
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
    weight_all_users = '3'
    weight_unknown = '10'

    memberRelationship = 'Member'
    indirectMemberRelationship = 'Indirect Member'
    ownerRelationship = 'Owner'
    permissionRelationship = 'Permission to Use'

    # Loop through our results and process the relationships
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
                # Find our target that we are working with
                if(x['Tag'] == "ApplicationName" or x['Tag'] =="ServicePrincipalName" or x['Tag'] =="UserName"):
                    targetName = x['Val']
                    names_list.append(targetName)
                
                
                # We have a Service Principal that has been granted consent for the tenant by a tenant admin
                if(x['Tag'] == "ServicePrincipalTenantPermissionGrantList"):
                    edges.append([targetName,name_all_users,weight_all_users, permissionRelationship])

                # We have a Service Principal that has been granted consent for a particular user
                if(x['Tag'] == "ServicePrincipalUserPermissionGrantList"):
                    for nameValuePair in x['Val']:
                        userList.append(nameValuePair['Item1'])
                        edges.append([targetName,nameValuePair['Item1'],weight_user, permissionRelationship])
                
                # We have a Service Principal that has been granted consent for a particular disabled user
                if(x['Tag'] == "ServicePrincipalDisabledUserPermissionGrantList"):
                    for nameValuePair in x['Val']:
                        disabledUserList.append(nameValuePair['Item1'])
                        edges.append([targetName,nameValuePair['Item1'],weight_disabled_user, permissionRelationship])

                # We have a Service Principal that has been granted consent for an AAD Object that is not recognized
                if(x['Tag'] == "ServicePrincipalUnknownObjectPermissionGrantList"):
                    for nameValuePair in x['Val']:
                        unknownObjectList.append(nameValuePair['Item1'])
                        edges.append([targetName,nameValuePair['Item1'],weight_unknown, permissionRelationship])

                # We have a Service Principal that is directly assigned as a member of an AAD Group
                if(x['Tag'] == "ServicePrincipalDirectGroupMember"):
                    for nameValuePair in x['Val']:
                        directGroupList.append(nameValuePair['Name'])
                        edges.append([targetName,nameValuePair['Name'],weight_group, memberRelationship])

                # We have a Service Principal that is directly assigned an AAD role membership
                if(x['Tag'] == "ServicePrincipalDirectRoleMember"):
                    for nameValuePair in x['Val']:
                        directRoleList.append(nameValuePair['Name'])
                        edges.append([targetName,nameValuePair['Name'],weight_role, memberRelationship])

                # We have a Service Principal that is directly assigned membership to an unknown AAD object
                if(x['Tag'] == "ServicePrincipalDirectUnknownMember"):
                    for nameValuePair in x['Val']:
                        directUnknownList.append(nameValuePair['Name'])
                        edges.append([targetName,nameValuePair['Name'],weight_unknown, memberRelationship])

                # We have a Service Principal that has indirect membership to a group e.g. SP is member of Group A, Group A is a member of Group B
                if(x['Tag'] == "ServicePrincipalIndirectGroupMember"):
                    for nameValuePair in x['Val']:
                        indirectGroupList.append(nameValuePair['Name'])
                        edges.append([targetName,nameValuePair['Name'],weight_group, indirectMemberRelationship])

                # We have a Service Principal that has indirect role membership e.g. SP is member of Group A, Group A is assigned Role B
                if(x['Tag'] == "ServicePrincipalIndirectRoleMember"):
                    for nameValuePair in x['Val']:
                        indirectRoleList.append(nameValuePair['Name'])
                        edges.append([targetName,nameValuePair['Name'],weight_role, indirectMemberRelationship])

                # We have a Service Principal that has indirect membership to an unknown AAD object
                if(x['Tag'] == "ServicePrincipalIndirectUnknownMember"):
                    for nameValuePair in x['Val']:
                        indirectUnknownList.append(nameValuePair['Name'])
                        edges.append([targetName,nameValuePair['Name'],weight_unknown, indirectMemberRelationship])

                # We have a user that is a member of an AAD Group
                if(x['Tag'] == "GroupMemberUser"):
                    userList.append(targetName)
                    for nameValuePair in x['Val']:
                        directGroupList.append(nameValuePair['Name'])
                        edges.append([targetName,nameValuePair['Name'],weight_group, memberRelationship])

                # We have a user that is a assigned a role membership
                if(x['Tag'] == "RoleMemberUser"):
                    userList.append(targetName)
                    for nameValuePair in x['Val']:
                        directRoleList.append(nameValuePair['Name'])
                        edges.append([targetName,nameValuePair['Name'],weight_role, memberRelationship])

                # We have a group that is a assigned a group membership
                if(x['Tag'] == "GroupMemberGroup"):
                    directGroupList.append(targetName)
                    for nameValuePair in x['Val']:
                        directGroupList.append(nameValuePair['Name'])
                        edges.append([targetName,nameValuePair['Name'],weight_group, memberRelationship])

                # We have a group that is a assigned a role membership
                if(x['Tag'] == "GroupMemberRole"):
                    directGroupList.append(targetName)
                    for nameValuePair in x['Val']:
                        directRoleList.append(nameValuePair['Name'])
                        edges.append([targetName,nameValuePair['Name'],weight_role, memberRelationship])

                # We have a user that is a assigned a group ownership
                if(x['Tag'] == "GroupOwners"):
                    userList.append(targetName)
                    for nameValuePair in x['Val']:
                        directGroupList.append(nameValuePair['Name'])
                        edges.append([targetName,nameValuePair['Name'],weight_user, ownerRelationship])

                # We have a user that is a assigned an application ownership
                if(x['Tag'] == "ApplicationOwner"):
                    userList.append(targetName)
                    for nameValuePair in x['Val']:
                        if('Name' in nameValuePair.keys()):
                            directApplicationList.append(nameValuePair['Name'])
                            edges.append([targetName,nameValuePair['Name'],weight_user, ownerRelationship])
                        elif('Id' in nameValuePair.keys()):
                            directApplicationList.append(nameValuePair['Id'])
                            edges.append([targetName,nameValuePair['Id'],weight_user, ownerRelationship])
                        else:
                            print('None')
                            directUnknownList.append(nameValuePair)
                            edges.append([targetName,nameValuePair,weight_unknown, ownerRelationship])

                # We have a user that is a assigned a service principal ownership
                if(x['Tag'] == "ServicePrincipalOwner"):
                    userList.append(targetName)
                    for nameValuePair in x['Val']:
                        directServicePrincipalList.append(nameValuePair['Name'])
                        edges.append([targetName,nameValuePair['Name'],weight_user, ownerRelationship])

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
                filewriter.writerow(edge)
                    
    # Take our list of objects and make a dropdown list to use for filtering
    names = sorted(set(names_list))
    name_dropdown = ipywidgets.Dropdown(options=names, description='Objects:')
    display(name_dropdown)

    return name_dropdown

def RenderGraphData(file_df):
    # Set up the Graph 
    G = nx.Graph
    modularity_class = {}
    modularity_color = {}
    relationship = {}

    # Process the passed in data frame and make nodes/edges data for graph
    # Use a data frame because networkx expects a data frame
    G = nx.from_pandas_edgelist(file_df, 'Source','Target', True)
    for index, row in file_df.iterrows():
        modularity_class[row['Source']] = 2
        modularity_color[row['Source']] = Spectral11[2]#Set3_12[2]
        modularity_class[row['Target']] = row['weight']
        modularity_color[row['Target']] = Spectral11[row['weight']]#Set3_12[row['weight']]
        relationship[row['Target']] = row['relationship']

    degrees = dict(nx.degree(G))
    nx.set_node_attributes(G, name='degree', values=degrees)

    # Set the node size after we have processed the data
    number_to_adjust_by = 10
    adjusted_node_size = dict([(node, degree+number_to_adjust_by) for node, degree in nx.degree(G)])
    nx.set_node_attributes(G, name='adjusted_node_size', values=adjusted_node_size)

    # Add modularity class, color, and relationship as attributes from the network above
    nx.set_node_attributes(G, modularity_class, 'modularity_class')
    nx.set_node_attributes(G, modularity_color, 'modularity_color')
    nx.set_node_attributes(G, relationship, 'relationship')


    #Choose attributes from G network to size and color by — setting manual size (e.g. 10) or color (e.g. 'skyblue') also allowed
    size_by_this_attribute = 'adjusted_node_size'
    color_by_this_attribute = 'modularity_color'

    #Choose a title!
    title = 'Azure Active Directory Network'

    #Establish which categories will appear when hovering over each node
    HOVER_TOOLTIPS = [
        ("Source", "@index"),
        ("Degree", "@degree"),
        ("Relationship", "@relationship"),
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
    # Given a list of edge data, parse out the items and format for use in HTML Tabulator Table display
    str = ''

    for item in list:
        str += '{Source:"' + item["Source"] + '", Target:"' + item["Target"] + '", relationship:"' + item["relationship"] + '", weight:"' + f"{item['weight']}" + '"},'
    
    return str

def htmlTreeParser(list):
    # Given a list of edge data, parse out the items and format for use in HTML Tabulator Tree display
    str = ''
    dict = {}

    # Load the dictionary with all the values
    for item in list:
        dict.setdefault(item["Source"], []).append((item["Target"], item["relationship"], item["weight"]))
    
    # Once all values found, trim the dictionary to unique values
    for key,value in dict.items():
        dict[key] = set(value)

    # Format all dictionary values for display with HTML Tabulator tree structure
    for key, value in dict.items():
        childrenString = ''
        for item in value:
            childrenString += '{Source:"' + item[0] + '", relationship:"' + item[1] + '", weight:"' + (f"{item[2]}") + '"},'
        str += '{Source:"' + key + '", _children:[' + childrenString + ']},'

    return str

def filterHelper(name_dropdown, file_df):
    # Based on given edge data CSV file and ipywidgets.Dropdown selection, filter the edge data
    if(name_dropdown.value != defaultFilter):
        file_df_filtered = file_df[(file_df.Target == name_dropdown.value)]
        file_df_filtered = file_df_filtered.append(file_df[(file_df.Source == name_dropdown.value)])
        return file_df_filtered
    else:
        return file_df

def filterDataFrameAndCreateList(name_dropdown, file_df):
    # Create a filtered list from given edge data CSV file and ipywidgets.Dropdown selection
    items = []
    file_df_filtered = filterHelper(name_dropdown, file_df)
    for index, row in file_df_filtered.iterrows():
        items.append(row)
    return items