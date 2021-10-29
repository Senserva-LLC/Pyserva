import unittest
#1
"""import Pyserva
from Pyserva import JupyterNotebookHelper as Senserva"""

#2
import sys
sys.path.append('C:\\Users\\Administrator\\Source\\Repos\\Senserva-LLC\\Pyserva\\src\\Pyserva')
import JupyterNotebookHelper as Senserva

#3
#import importlib.util

class Test_test_jupyterNoteBookHelper(unittest.TestCase):
    def test_SenservaPermissionQuery(self):
        rtn = Senserva.SenservaPermissionQuery('SenservaPro_CL')
        self.assertEqual(rtn, "SenservaPro_CL | where TimeGenerated > ago(7d)| where (ControlName_s == 'ServicePrincipalPermissionGrantTenant' or ControlName_s == 'ApplicationPermissionGrantTenant' or ControlName_s == 'ServicePrincipalMembership' or ControlName_s == 'UserMembers' or ControlName_s =='UserOwners' or ControlName_s =='GroupMembers') | extend values =tostring(parse_json(Value_s)) | extend JSON = todynamic(values) | order by TimeGenerated desc")

    def test_has_valid_token(self):
        rtn = Senserva.has_valid_token()
        self.assertEqual(rtn, True)

    def test_read_config_values(self):   
        tenant_id, subscription_id, resource_group, workspace_id, workspace_name, user_alias, user_object_id = \
                 Senserva.read_config_values('config.json')
        self.assertEqual(tenant_id, 'tenant_id_test_data')
        self.assertEqual(subscription_id, 'subscription_id_test_data')
        self.assertEqual(resource_group, 'resource_group_test_data')
        self.assertEqual(workspace_id, 'workspace_id_test_data')
        self.assertEqual(workspace_name, 'workspace_name_test_data')
        self.assertEqual(user_alias, 'user_alias_test_data')
        self.assertEqual(user_object_id, 'user_object_id_test_data')

    def test_read_config_values_except(self):
        try:           
            rtn = Senserva.read_config_values()
        except Exception:        
            pass  
             

if __name__ == '__main__':
   unittest.main()
