
# Load Python libraries that will be used in this notebook
from azure.common.client_factory import get_client_from_cli_profile
from azure.common.credentials import get_azure_cli_credentials
from azure.loganalytics.models import QueryBody
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.loganalytics import LogAnalyticsDataClient

# Processing Helpers
import pandas as pd
import numpy as np
import ipywidgets
from IPython.display import display, HTML, Markdown
import json
import networkx as nx
import csv
import requests
import jsonpickle

from io import BytesIO
import msal
import logging

#Bokeh Visualization Helpers
import bokeh.io
from bokeh.io import output_notebook, show, save
from bokeh.models import Range1d, Circle, ColumnDataSource, MultiLine
from bokeh.plotting import figure, from_networkx
from bokeh.palettes import RdYlGn11
from bokeh.transform import linear_cmap
from bokeh.resources import INLINE
bokeh.io.output_notebook(INLINE)
import scipy
import tkinter as tk

# Globals
token = None
graphApiVersion = "beta"
uri = "https://graph.microsoft.com/{v}/{r}"
headers = None

# Functions
def authenticate(tenant: str, id: str, secret: str):
    global token
    global headers
    authority = "https://login.microsoftonline.com/{0}".format(tenant)
    appID = id
    appSecret = secret
    scope = ["https://graph.microsoft.com/.default"]

    app = msal.ConfidentialClientApplication(
        appID, authority=authority, client_credential = appSecret)
    token = app.acquire_token_silent(scope, account=None)
    if not token:
        token = app.acquire_token_for_client(scopes=scope)
    headers = {'Authorization': 'Bearer ' + token['access_token']}
    return

def users():
    return query(graphApiVersion, "users?")

def usersMemberships():
    return query(graphApiVersion, "users?$expand=memberOf")

def usersManagers():
    return query(graphApiVersion, "users?$expand=manager")

def groups():
    return query(graphApiVersion, "groups")

def groupsMemberships():
    return query(graphApiVersion, "groups?$expand=members")

def groupsOwners():
    return query(graphApiVersion, "groups?$expand=owners")

def roles():
    return query(graphApiVersion, "directoryRoles")

def rolesMembers():
    return query(graphApiVersion, "directoryRoles?$expand=members")

def applications():
    return query(graphApiVersion, "applications")

def applicationsOwners():
    return query(graphApiVersion, "applications?$expand=owners")

def servicePrincipals():
    return query(graphApiVersion, "servicePrincipals")

def servicePrincipalsOwners():
    return query(graphApiVersion, "servicePrincipals?$expand=owners")

def query(v, r):
    dest = uri.format(v=v, r=r)
    result = requests.get(dest, headers=headers).json()

    test = getNextLinkQuery(result)

    while test is not None:
        result["value"].extend(test["value"])
        test = getNextLinkQuery(test)
        
    return result

def getNextLinkQuery(result):
    if "@odata.nextLink" in result:
        newResult = requests.get(result["@odata.nextLink"], headers=headers).json()
        return newResult
    return

# *********************

def PluckDataFromQueryResults(userMemberDict, userManagerDict, groupOwnerDict, groupMemberDict, roleMemberDict, appOwnerDict, spDict, filewriter): 
    
    filewriter.writerow(['Source', 'SourceId', 'SourceType', 'Target', 'TargetId', 'TargetType', 'SourceWeight', 'TargetWeight', 'Relationship', 'Reason', 'Risk', 'UserMail', 'UserManagerMail'])

    # Set up some values
    role_member_relationship = 'Role Member'
    group_member_relationship = 'Group Member'
    group_owner_relationship = 'Group Owner'
    app_owner_relationship = 'Application Owner'
    service_principal_owner_relationship = 'Service Principal Owner'
    manager_relationship = 'Manager'
    unknown_relationship = 'Unknown'

    very_low_risk = 'VeryLow'
    low_risk = 'Low'
    medium_risk = 'Medium'
    high_risk = 'High'
    very_high_risk = 'VeryHigh'
    

    weight_user = '1'
    weight_disabled_user = '3'
    weight_group = '4'
    weight_role = '5'
    weight_app = '9'
    weight_unknown = '10'

    user_type = "User"
    disabled_user_type = "Disabled User"
    group_type = "Group"
    role_type = "Role"
    app_type = "Application"
    service_principal_type = "Service Principal"
    unknown_type = "Unknown"
    
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

    if "value" in userMemberDict:
        for user in userMemberDict["value"]:
            processingHelper(user["displayName"])
            userMail = user['mail']
            userManagerMail = ''
            risk = low_risk
            weight = MapRiskToValue(risk)
            usertype = user_type

            if user["accountEnabled"] == True:
                userList.append(user["displayName"])
            else:
                disabledUserList.append(user["displayName"])
                usertype = disabled_user_type
                weight = weight_disabled_user
                risk = medium_risk
                weight = MapRiskToValue(risk)

            if "memberOf" in user:
                for userMembership in user["memberOf"]:
                    if userMembership["@odata.type"] == "#microsoft.graph.directoryRole":
                        directRoleList.append(userMembership["displayName"])

                        if("Global Administrator" in userMembership["displayName"]):
                            risk = high_risk
                            weight = MapRiskToValue(risk)
                        elif("Administrator" in userMembership["displayName"]):
                            risk = medium_risk
                            weight = MapRiskToValue(risk)

                        edges.append([user["displayName"], user["id"], usertype, userMembership["displayName"],userMembership["id"], role_type,weight, weight, role_member_relationship, role_member_relationship, risk, userMail, userManagerMail])
                    elif userMembership["@odata.type"] == "#microsoft.graph.group":
                        directGroupList.append(userMembership["displayName"])
                        edges.append([user["displayName"], user["id"],usertype,userMembership["displayName"],userMembership["id"],group_type,weight, weight, group_member_relationship, group_member_relationship, risk, userMail, userManagerMail])
                    else:
                        unknownObjectList.append(userMembership["id"])
                        edges.append([user["displayName"], user["id"],usertype,userMembership["displayName"],userMembership["id"],unknown_type, weight, weight, unknown_relationship, unknown_relationship, medium_risk, userMail, userManagerMail])

    if "value" in userManagerDict:
        for user in userManagerDict["value"]:
            processingHelper(user["displayName"])
            userMail = user['mail']
            userManagerMail = ''
            risk = very_low_risk
            weight = MapRiskToValue(risk)
            usertype = user_type
            
            if user["accountEnabled"] == True:
                userList.append(user["displayName"])
                weight = weight_user
            else:
                disabledUserList.append(user["displayName"])
                usertype = disabled_user_type
                weight = weight_disabled_user
                risk = low_risk
                weight = MapRiskToValue(risk)

            if "manager" in user:
                userManager = user["manager"]
                if "mail" in userManager:
                    userManagerMail = userManager["mail"]
                edges.append([user["displayName"], user["id"],usertype,userManager["displayName"],userManager["id"],user_type,weight, weight, manager_relationship, manager_relationship, risk, userMail, userManagerMail])

    if "value" in groupOwnerDict:
        for group in groupOwnerDict["value"]:
            processingHelper(group["displayName"])
            groupMail = group['mail']
            groupManagerMail = group['mail']
            directGroupList.append(group["displayName"])
            risk = medium_risk
            weight = MapRiskToValue(risk)

            for owner in group["owners"]:
                for user in userMemberDict["value"]:
                    if owner["id"] == user["id"]:
                        usertype = user_type
                        if user["accountEnabled"] == True:
                            userList.append(user["displayName"])
                            weight = MapRiskToValue(risk)
                        else:
                            disabledUserList.append(user["displayName"])
                            usertype = disabled_user_type
                            weight = weight_disabled_user
                            risk = high_risk
                            weight = MapRiskToValue(risk)
                        edges.append([group["displayName"], group["id"],group_type,user["displayName"],user["id"],usertype,weight, weight, group_owner_relationship, group_owner_relationship, risk, groupMail, groupManagerMail])

    if "value" in groupMemberDict:
        for group in groupMemberDict["value"]:
            processingHelper(group["displayName"])
            groupMail = group['mail']
            groupManagerMail = group['mail']
            directGroupList.append(group["displayName"])
            risk = low_risk
            weight = MapRiskToValue(risk)

            for member in group["members"]:
                for user in userMemberDict["value"]:
                    if member["id"] == user["id"]:
                        usertype = user_type
                        if user["accountEnabled"] == True:
                            userList.append(user["displayName"])
                            weight = MapRiskToValue(risk)
                        else:
                            disabledUserList.append(user["displayName"])
                            usertype = disabled_user_type
                            risk = medium_risk
                            weight = MapRiskToValue(risk)
                        edges.append([group["displayName"], group["id"],group_type,user["displayName"],user["id"],usertype,weight, weight, group_member_relationship, group_member_relationship, risk, groupMail, groupManagerMail])
                for innerGroup in groupMemberDict["value"]:
                    if member["id"] == innerGroup["id"]:
                        directGroupList.append(innerGroup["displayName"])
                        risk = medium_risk
                        weight = MapRiskToValue(risk)
                        edges.append([group["displayName"], group["id"],group_type,innerGroup["displayName"],innerGroup["id"],group_type,weight, weight, group_member_relationship, group_member_relationship, risk, groupMail, groupManagerMail])

    if "value" in roleMemberDict:
        for role in roleMemberDict["value"]:
            processingHelper(role["displayName"])
            roleMail = ''
            roleManagerMail = ''
            directRoleList.append(role["displayName"])

            if("Global Administrator" in role["displayName"]):
                risk = high_risk
            elif("Administrator" in role["displayName"]):
                risk = medium_risk
            else:
                risk = low_risk

            weight = MapRiskToValue(risk)
                
            for member in role["members"]:
                for user in userMemberDict["value"]:
                    if member["id"] == user["id"]:
                        usertype = user_type
                        if user["accountEnabled"] == True:
                            userList.append(user["displayName"])
                        else:
                            disabledUserList.append(user["displayName"])
                            usertype = disabled_user_type
                            weight = weight_disabled_user

                            if("Global Administrator" in role["displayName"]):
                                risk = very_high_risk
                            elif("Administrator" in role["displayName"]):
                                risk = high_risk
                            else:
                                risk = medium_risk
                            
                            weight = MapRiskToValue(risk)

                        edges.append([role["displayName"], role["id"],role_type,user["displayName"],user["id"],usertype,weight_role, weight, role_member_relationship, role_member_relationship, risk, roleMail, roleManagerMail])
                for group in groupMemberDict["value"]:
                    if member["id"] == group["id"]:
                        directGroupList.append(group["displayName"])
                        weight = weight_group
                        risk = medium_risk
                        edges.append([role["displayName"], role["id"],role_type,group["displayName"],group["id"],group_type,weight_role, weight, role_member_relationship, role_member_relationship, risk, roleMail, roleManagerMail])

    if "value" in appOwnerDict:
        for application in appOwnerDict["value"]:
            processingHelper(application["displayName"])
            appMail = ''
            appManagerMail = ''
            risk = low_risk
            directApplicationList.append(application["displayName"])
            weight = MapRiskToValue(risk)

            for owner in application["owners"]:
                for user in userMemberDict["value"]:
                    if owner["id"] == user["id"]:
                        usertype = user_type
                        if user["accountEnabled"] == True:
                            userList.append(user["displayName"])
                        else:
                            disabledUserList.append(user["displayName"])
                            usertype = disabled_user_type
                            risk = high_risk
                        
                        weight = MapRiskToValue(risk)
                        edges.append([application["displayName"], application["id"],app_type,user["displayName"],user["id"],usertype,weight, weight, app_owner_relationship, app_owner_relationship, risk, appMail, appManagerMail])


    if "value" in spDict:
        for servicePrincipal in spDict["value"]:
            processingHelper(servicePrincipal["displayName"])
            spMail = ''
            spManagerMail = ''
            risk = medium_risk
            directServicePrincipalList.append(servicePrincipal["displayName"])
            weight = MapRiskToValue(risk)

            for owner in servicePrincipal["owners"]:
                for user in userMemberDict["value"]:
                    if owner["id"] == user["id"]:
                        usertype = user_type
                        if user["accountEnabled"] == True:
                            userList.append(user["displayName"])
                        else:
                            disabledUserList.append(user["displayName"])
                            usertype = disabled_user_type
                            risk = high_risk
                        
                        weight = MapRiskToValue(risk)
                        edges.append([servicePrincipal["displayName"], servicePrincipal["id"],service_principal_type, user["displayName"],user["id"],usertype,weight, weight, service_principal_owner_relationship, service_principal_owner_relationship, risk, spMail, spManagerMail])

    defaultFilter = '(no filter applied)'
    dropdown = [defaultFilter]
    for user in userList:
        dropdown.append(user)
    for disabledUser in disabledUserList:
        dropdown.append(disabledUser)
    for group in directGroupList:
        dropdown.append(group)
    for role in directRoleList:
        dropdown.append(role)
    for servicePrincipal in directServicePrincipalList:
        dropdown.append(servicePrincipal)
    for application in directApplicationList:
        dropdown.append(application)
    for unknown in directUnknownList:
        dropdown.append(unknown)
    for edge in edges:
        filewriter.writerow(edge)

    return

def filterHelper(name_dropdown, file_df, defaultFilter):
    # Based on given edge data file and dropdown selection, filter the edge data
    if(name_dropdown.value != defaultFilter):
        file_df_filtered = file_df[(file_df.Target == name_dropdown.value)]
        file_df_filtered = file_df_filtered.append(file_df[(file_df.Source == name_dropdown.value)])
        return file_df_filtered
    else:
        return file_df
   

def processingHelper(item: str):
    print("Processing " + item + "...")

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
    target_id = {}
    target_type = {}

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
        modularity_color[row['Source']] = RdYlGn11[keys[row['Target']]]
        modularity_class[row['Target']] = keys[row['Source']]
        modularity_color[row['Target']] = RdYlGn11[keys[row['Target']]]
        relationship[row['Target']] = row['Relationship']
        target_id[row['Source']] = row['SourceId']
        target_id[row['Target']] = row['TargetId']
        target_type[row['Source']] = row['SourceType']
        target_type[row['Target']] = row['TargetType']

        if(row['Source'] in risk.keys()):
            risk[row['Source']] = RiskComparer(risk[row['Source']], row['Risk'])
        else:
            risk[row['Source']] = row['Risk']

        if(row['Target'] in risk.keys()):
            risk[row['Target']] = RiskComparer(risk[row['Target']], row['Risk'])
        else:
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
    nx.set_node_attributes(G, target_id, 'target_id')
    nx.set_node_attributes(G, target_type, 'target_type')



    #Choose attributes from G network to size and color by — setting manual size (e.g. 10) or color (e.g. 'skyblue') also allowed
    size_by_this_attribute = 'adjusted_node_size'
    color_by_this_attribute = 'modularity_color'

    #Choose a title!
    title = 'Needle in the Haystack'

    #Establish which categories will appear when hovering over each node
    HOVER_TOOLTIPS = [
        ("Azure Name", "@index"),
        ("Azure ID", "@target_id"),
        ("Azure Object Type", "@target_type"),
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

    return plot

def filterDataFrame(name_dropdown, file_df):
    items = []
    #file_df_filtered = filterHelper(name_dropdown, file_df)
    for index, row in file_df.iterrows():
        items.append(row)
    return items


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
        # token = creds._token_retriever()[2]
        token = creds.get_token()[1]
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

    where_clause = "{0} | where TimeGenerated > ago(7d)| where (ControlName_s == 'ServicePrincipalPermissionGrantTenant' or ControlName_s == 'ApplicationPermissionGrantTenant' or ControlName_s == 'ServicePrincipalMembership' or ControlName_s == 'UserMembers' or ControlName_s =='UserOwners' or ControlName_s =='GroupMembers' or ControlName_s == 'UserManagers') | extend values =tostring(parse_json(Value_s)) | extend JSON = todynamic(values) | order by TimeGenerated desc"
    return where_clause.format(tableName)

def ParseQueryResultHelper(nameValuePair, foundList, defaultList, edgesList, primaryKey, backupKey, sourceName, weightSource, weightFound, weightNotFound, relationship, risk, userMail,userManagerMail):
    '''Helper to parse through query results TODO: Add Reason'''

    if(primaryKey in nameValuePair.keys()):
        foundList.append(nameValuePair[primaryKey])
        edgesList.append([sourceName,nameValuePair[primaryKey],weightSource,weightFound, relationship, "TBD", MapRisk(risk),userMail,userManagerMail])
    elif(backupKey in nameValuePair.keys()):
        foundList.append(nameValuePair[backupKey])
        edgesList.append([sourceName,nameValuePair[backupKey],weightSource,weightFound, relationship,"TBD", MapRisk(risk),userMail,userManagerMail])
    else:
        defaultList.append(nameValuePair)
        edgesList.append([sourceName,nameValuePair,weightSource,weightNotFound, relationship,"TBD", MapRisk(risk),userMail,userManagerMail])
    
    return (foundList, defaultList, edgesList)

def MapRisk(risk):
    '''Map the Risk Value to a Name'''

    return risk

def htmlTableParser(list):
    '''Given a list of edge data, parse out the items and format for use in HTML Tabulator Table display'''

    str = ''
    dict = {}

    # Load the dictionary with all the values
    for item in list:
        dict.setdefault(item["Source"], []).append((item["Target"], item["relationship"], item["weight"]))

    # Once all values found, trim the dictionary to unique values
    for key,value in dict.items():
        dict[key] = set(value)
    
    # Format all dictionary values for display with HTML Tabulator table structure
    for key, value in dict.items():
        for item in value:
            str += '{Source:"' + key + '", ' + 'Target:"' + item[0] + '", relationship:"' + item[1] + '", weight:"' + f"{item[2]}" + '"},'

    return str

def RiskComparer(current, new):
    highest = 'Unknown'
    if(MapRiskToValue(current) > MapRiskToValue(new)):
        highest = current
    else:
        highest = new

    return highest

def MapRiskToValue(risk):
    dict = {'Unknown': -1, 'None': 0, 'VeryLow': 1, 'Low': 3, 'Medium': 5, 'High': 7, 'VeryHigh': 9, 'Critical': 11}

    return dict[risk] if risk in dict else -1

def filterDataFrameAndCreateList(name_dropdown, file_df, defaultFilter):
    '''Create a filtered list from given edge data CSV file and ipywidgets.Dropdown selection'''

    items = []
    #file_df_filtered = filterHelper(name_dropdown, file_df, defaultFilter)
    for index, row in file_df.iterrows():
        items.append(row)
    return items

def demoData(file_df):
    items = []
    for index, row in file_df.iterrows():
        temp = row.to_dict()
        items.append(temp.get('Source'))
        items.append(temp.get('Target'))
    return items
    

def htmlTreeParser(list):
    '''Given a list of edge data, parse out the items and format for use in HTML Tabulator Tree display'''

    str = ''
    dict = {}
    highestWeight = 0
    highestRisk = 'None'

    # Load the dictionary with all the values
    for item in list:
        key_ls = LongShort(f'{item["Source"]}({item["SourceId"]})',item["Source"])
        target_ls = LongShort(f'{item["Target"]}({item["TargetId"]})',item["Target"])
        dict.setdefault((jsonpickle.encode(key_ls, unpicklable=False).replace('"',"'"),item["SourceType"]), []).append((jsonpickle.encode(target_ls, unpicklable=False).replace('"',"'"), item["TargetType"],item["Relationship"], item["Reason"], item["Risk"], item["TargetWeight"], item["UserMail"], item["UserManagerMail"]))
    
    # Once all values found, trim the dictionary to unique values
    for key,value in dict.items():
        dict[key] = set(value)

    # Format all dictionary values for display with HTML Tabulator tree structure
    for key, value in dict.items():
        highestWeight = 0
        highestRisk = 'None'
        userMail = ''
        userManagerMail = ''
        reason = ''
        childrenString = ''
        relationship = ''
        target_type = ''
        for item in value:
            highestRisk = RiskComparer(highestRisk, item[4])
            highestWeight = highestWeight if (highestWeight > (2*item[5])) else (2*item[5])
            if(not(isNaN(item[1]))):
                target_type = item[1]
            if(not(isNaN(item[2]))):
                relationship = item[2]
            if(not(isNaN(item[3]))):
                reason =  item[3]
            if(not(isNaN(item[6]))):
                userMail =  item[6]
            if(not(isNaN(item[7]))):
                userManagerMail =  item[7]
            childrenString += '{Source:"' + item[0] + '", type:"' + target_type + '", relationship:"' + relationship + '", reason:"' + reason + '", risk:"' + item[4] + '", weight:"' + (f"{2*item[5]}") + '", overall:"' + (f"{MapRiskToValue(item[4]) * 8*item[5]}") + '"},'
        str += '{Source:"' + key[0] + '",type:"' + key[1] + '", risk:"' + highestRisk + '", weight:"' + (f"{highestWeight}") + '", overall:"' + (f"{MapRiskToValue(highestRisk) * highestWeight}") + '", mailLink:"' + userMail + '", managerMailLink:"' + userManagerMail + '", _children:[' + childrenString + ']},'

    return str

def isNaN(string):
    return string != string


def getTreeTemplate():
    treeTemplate = '''<link href="https://unpkg.com/tabulator-tables@5.0.6/dist/css/tabulator.min.css" rel="stylesheet">
<script type="text/javascript" src="https://unpkg.com/tabulator-tables@5.0.6/dist/js/tabulator.min.js"></script>
<link href='https://unpkg.com/tabulator-tables@5.0.6//dist/css/tabulator_midnight.min.css' rel='stylesheet'>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.4.0/jspdf.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.20/jspdf.plugin.autotable.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.3.2/html2canvas.min.js"></script>
<div>
    <input id='reactivity-includeIds', type='checkbox' name='ids'>
    <label for='ids'> Verbose</label>
</div>
<div>
    <button id="download-csv">Download CSV</button>
    <button id="download-pdf">Download PDF</button>
</div>

<div id="senserva-table"></div>

<script>

    var useLongText = false;

document.getElementById('reactivity-includeIds').addEventListener('click', function () {{
        var checkbox = document.getElementById('reactivity-includeIds');
        useLongText = checkbox.checked;
        table.toggleColumn('type');
        table.replaceData(tableDataNested); 
    }});

document.getElementById("download-csv").addEventListener("click", function(){{
            body = [];
            cols = ['Interactions', 'Relationship', 'Reason', 'Risk', 'Impact', 'Overall', 'Mail Link'];
            if (useLongText) {{
                cols = ['Interactions', 'Object Type', 'Relationship', 'Reason', 'Risk', 'Impact', 'Overall', 'Mail Link'];
            }}
            body = parseRows(table.getData(), body);

            var csvContent = "data:text/csv;charset=utf-8,"

            csvContent += cols.join(",") + "\\r\\n"

            body.forEach(function (rowArray) {{
                var row = rowArray.join(",");
                csvContent += row.replaceAll('#', '') + "\\r\\n"
            }})

            var encodedUri = encodeURI(csvContent);
            var link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", "SenservaConnectionsContent.csv");
            document.body.appendChild(link);
            link.click();
}});

document.getElementById("download-pdf").addEventListener("click", function(){{
            body = [];
            cols = ['Interactions', 'Relationship', 'Reason', 'Risk', 'Impact', 'Overall', 'Mail Link'];
            if (useLongText) {{
                cols = ['Interactions', 'Object Type', 'Relationship', 'Reason', 'Risk', 'Impact', 'Overall', 'Mail Link'];
            }}
            body = parseRows(table.getData(), body);
            const doc = new jspdf.jsPDF();

            doc.autoTable(cols, body);
            doc.save("SenservaConnectionsContent.pdf");
}});

// non list search using text
    function customHeaderFilterForString(headerValue, rowValue, rowData, filterParams) {{
        //headerValue - the value of the header filter element
        //rowValue - the value of the column in this row
        //rowData - the data for the row being filtered
        //filterParams - params object passed to the headerFilterFuncParams property
        if (headerValue) {{
            var testString = headerValue.toLowerCase();
            if (rowValue) {{
                if (testString.startsWith('!')) {{
                    if(!rowValue.toLowerCase().includes(testString.substring(1))) {{
                        return true;
                    }}
                }}
                else {{
                    if (rowValue.toLowerCase().includes(testString)) {{
                        return true;
                    }}
                }}
            }}

            if (rowData && rowData._children) {{
                var found = false
                rowData._children.forEach(function (element) {{
                    found = found || element[filterParams].toLowerCase().includes(testString)
                }})
                return found
            }}
        }}
        else {{
            return true; // no search
        }}
        return false;
    }}
        
        function checkProperty(row, nameOfProperty) {{
            if (nameOfProperty in row) {{
                return row[nameOfProperty]
            }}
            else {{
                return ' '
            }}
        }}

        function parseRow(row) {{
            var retVal = []
            
            const obj = JSON.parse(checkProperty(row, 'Source').replace(/'/g, '"'));
            if (useLongText) {{
                retVal.push(obj['long'])
                retVal.push(checkProperty(row, 'type'))
            }}
            else {{
                retVal.push(obj['short'])
            }}
            retVal.push(checkProperty(row, 'relationship'))
            retVal.push(checkProperty(row, 'reason'))
            retVal.push(checkProperty(row, 'risk'))
            retVal.push(checkProperty(row, 'weight'))
            retVal.push(checkProperty(row, 'overall'))
            retVal.push(checkProperty(row, 'mailLink'))

            return retVal
        }}

        function parseRows(data, body) {{
            //build table rows
            data.forEach(function (row) {{
                getChildData(row, body);
            }});

            return body;
        }}

        // helper recursive function to fetch child data
        function getChildData(parent, body) {{
            var parent_data = Object.assign({{}}, parent);
            delete parent_data["_children"];
            body.push(parseRow(parent_data));
            if ("_children" in parent) {{
                for (var i = 0, l = parent["_children"].length; i < l; ++i) {{
                    var child = parent["_children"][i];
                    getChildData(child, body);
                }}
            }}
        }}

        

    var populate = function (cell) {{

        try {{
            var inter = cell.getValue().replace(/'/g, '"');
            const obj = JSON.parse(cell.getValue().replace(/'/g, '"'));
                    var s = obj['short'];
                    if (useLongText) {{
                            s = obj['long'];
                    }}
                    var el = cell.getElement();
                    el.style.whiteSpace = 'pre-wrap';
                    el.style.overflow = 'auto';
                    el.style.maxHeight = '100px';
                    return s;
            }}
            catch (err) {{
                    return "<none>";
            }}
    }};

var tableDataNested = [{inputData}];

var table = new Tabulator('#senserva-table', {{
    height: '70%',
    data: tableDataNested,
    dataTree: true,
    dataTreeFilter: false,
    clipboard: true,
    downloadRowRange: 'active',
    pagination:'local',
    paginationSizeSelector:[10, 25, 50, 100],
    paginationSize:10,
    footerElement: "<a href='https:\\www.senserva.com'><button>Powered by Senserva</button></a>",
    columns: [
        {{
            title: 'Interactions',
            field: 'Source',
            width: '20%',
            headerFilter: "input",
            headerFilterFunc: customHeaderFilterForString,
            headerFilterFuncParams: "Source",
            headerTooltip: 'Interactions between AD objects',
            tooltip: 'Interactions',
            formatter:function(cell, formatterParams, onRendered){{
                var data = populate(cell);
                return this.emptyToSpace(this.sanitizeHTML(data));
            }}
        }}, 
        {{
            title: 'Object Type',
            field: 'type',
            width: '10%',
            headerFilter: "input",
            headerFilterFunc: customHeaderFilterForString,
            headerFilterFuncParams: "type",
            headerTooltip: 'The type of the Azure object',
            tooltip: 'Object Type',
            visible: false
        }},
        {{
            title: 'Relationship',
            field: 'relationship',
            width: '15%',
            headerFilter: "input",
            headerFilterFunc: customHeaderFilterForString,
            headerFilterFuncParams: "relationship",
            headerTooltip: 'Relationships between AD objects',
            tooltip: 'Relationships', 
        }},
        {{
            title: 'Insights',
            field: 'reason',
            formatter:function(cell, formatterParams, onRendered){{
                var el = cell.getElement();
                el.style.whiteSpace = 'pre-wrap';
                el.style.overflow = 'auto';
                el.style.maxHeight = '75px';
                return this.emptyToSpace(this.sanitizeHTML(cell.getValue()));
            }},
            width: '20%',
            headerFilter: 'input',
            headerFilterFunc: customHeaderFilterForString,
            headerFilterFuncParams: "reason",
            headerTooltip: 'Insights about AD objects',
            tooltip: 'Insights', 
        }},
        {{
            title: 'Risk',
            field: 'risk',
            width: '10%',
            headerFilter: 'input',
            headerFilterFunc: customHeaderFilterForString,
            headerFilterFuncParams: "risk",
            headerTooltip: 'Senserva evaluated Risk to the network',
            tooltip: 'Risk', 
        }},
        {{
            title: 'Impact',
            field: 'weight',
            align: 'center',
            width: '10%',
            formatter:'progress', 
            formatterParams:{{color:['green', 'orange', 'red']}},
            tooltip:true,
            sorter:"number",
            headerTooltip: 'Senserva evaluated Potential to the network',
            tooltip: 'Impact', 
        }}, 
        {{
            title: 'Overall',
            field: 'overall',
            align: 'center',
            width: '15%',
            formatter:'progress', 
            formatterParams:{{color:['green', 'orange', 'red']}},
            tooltip:true,
            sorter:"number",
            headerTooltip: 'Senserva evaluated Overall threat to the network',
            tooltip: 'Overall', 
        }}, 
        {{
            title: 'Mail Link',
            field: 'mailLink',
            width: '10%',
            headerTooltip: 'Mailto link to AD object and Manager (if available)',
            tooltip: 'Mail Link', 
            formatter:function(cell, formatterParams, onRendered){{
                //cell - the cell component
                //formatterParams - parameters set for the column
                //onRendered - function to call when the formatter has been rendered

                var sendTo = cell.getValue()
                if(sendTo === undefined || sendTo == '')
                {{
                    var el = document.createElement("p")
                    el.innerHTML = "N/A"

                    return el;
                }}

                var ccTo = cell.getData().managerMailLink;
                if(ccTo === undefined)
                {{
                    ccTo = ''
                }}

                var el = document.createElement("a");
                el.setAttribute("href", "mailto://" + cell.getValue() + "?subject=Senserva Connections Data Report Results&cc=" + ccTo)
                el.innerHTML = "Email"
            
                return el; //return the contents of the cell;
            }},
        }},
        {{
            field: 'managerMailLink',
            visible: false
        }}
    ],
    initialSort:[
        {{column:"overall", dir:"desc"}}, 
        {{column:"weight", dir:"desc"}}, 
    ]
}});
</script>'''
    return treeTemplate

def getReportTemplate():
    reportTemplate = '''<!DOCTYPE html>
<html>
<head>
<div><a href="https:\\www.senserva.com"><img src="https://github.com/Senserva-LLC/SenservaResources/blob/main/HTMLResources/SSL-Logo+Workmark--Vertical--Color.png?raw=true" height="75"></a></div>
<title>Senserva Connections Scanner Report</title>
</head>
<body style="margin-left: auto; margin-right: auto; text-align:center; font-family: sans-serif; padding-right: 10%; padding-left: 10%; ">

<h1>Senserva Connections Scanner Report</h1>
<table>
<tr>
<td>Welcome to the report for your Senserva Connections Scan results! Our team prides itself on clear, accurate reporting of your Connections.</td>
<td>This report will evaluate Users, Groups, Roles, Applications, and Service Principals. Senserva's Pro Scanner will evaluate more metrics such 
as Permissions, PIM Roles, Conditional Access Usage, and more!</td>
<td>The table of results below shows graded connections that exist in your Azure cloud, ordered on risk level. Risk level is calculated based on several factors including as user status, power of role, and type of relationship.</td>
</tr>
</table>
<br/>
<br/>

<div style="maxHeight: 20px; overflow-y: scroll;text-align:left">{table_input}</div>
<br/>
<br/>

<p>Here is a visual network graph of the connections that exist.</p>
<div style="display: flex; justify-content: center;">{graph_input}</div>

</body>
</html>
'''
    return reportTemplate


class LongShort():
  def __init__(self, long, short):
    self.long = long
    self.short = short