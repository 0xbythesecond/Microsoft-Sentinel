# Microsoft Sentinel

![Microsoft Sentinel (1)](https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/4ffe3cc6-a155-460f-81d0-5b0531d64cac)
 

## Implement Microsoft Sentinel

Duration: 30 minutes

Introduction:
In this exercise, you will learn how to implement Microsoft Sentinel, a cloud-native Security Information and Event Management (SIEM) solution provided by Microsoft. You will perform various tasks, including on-boarding Microsoft Sentinel, connecting Azure Activity to Sentinel, creating rules, playbooks, and custom alerts, and reviewing associated actions.

<details>

<summary>
  
### Task 1: On-board Microsoft Sentinel
  
</summary>  

1. Sign in to the Azure portal `https://portal.azure.com` using an account that has the Owner or Contributor role in the Azure subscription.

2. In the Azure portal, search for "Microsoft Sentinel" in the Search resources, services, and docs text box.

3. On the Microsoft Sentinel blade, click "+ Create" to start the on-boarding process.

4. On the "Add Microsoft Sentinel to a workspace" blade, select the Log Analytics workspace you created in the Azure Monitor lab and click "Add".
  
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/b3efe8ae-c8c4-4b67-93e8-ba86a9e1c20c" height="80%" width="80%" alt="Add Microsoft Sentinel to LAW"/>

</details>

#

<details>

<summary>  

### Task 2: Connect Azure Activity to Sentinel
  
</summary>  

1. On the Microsoft Sentinel blade, go to the Configuration section and click "Data connectors".

2. On the Data connectors blade, search for "Azure" and select the Azure Activity data connector.
  
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/633ef6c4-6f1a-4eca-ab5a-82f40c0fe1e9" height="80%" width="80%" alt="Azure Activity Data Connectors"/>
  

3. On the Azure Activity blade, follow the instructions to configure the connector. This includes connecting your subscriptions through diagnostic settings using the Azure Policy Assignment wizard.
  
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/ce0a9355-c468-4926-b6b3-3d3cea1c6525" height="40%" width="40%" alt="Open Connector Page"/>  
  
Launch Policy Assignment Wizard  
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/f51edc30-fbd0-4a74-b1ec-aa28556ae86e" height="90%" width="90%" alt="Launch Azure Policy Assignment Wizard"/>
  
  
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/b1842d10-3d18-44a7-a9ab-cd767d791827" height="70%" width="70%" alt="Select Scope for Azure Activity Policy"/>

  >**Note**: Do not choose a Resource Group

Select Workspace for Azure Activity Policy
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/af85a06d-22c8-4b08-8cf7-ba0cf073027a" height="80%" width="80%" alt="Select Workspace for Azure Activity Policy"/>
  
Create a Remediation Task  
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/e4869db2-91af-403f-a4a0-452228a4da48" height="90%" width="90%" alt="Create a Remediation Task"/>
  
Click the Next button at the bottom of the Remediation tab to proceed to the Non-compliance message tab. Enter a Non-compliance message if you wish (this is optional) and click the Review + Create button at the bottom of the Non-compliance message tab.  
  
Click the Create button. You should observe three succeeded status messages: Creating policy assignment succeeded, Role Assignments creation succeeded, and Remediation task creation succeeded.  
  
4. Review and confirm the successful configuration of the Azure Activity data connector.
  
  >**Note**: You can check the Notifications, bell icon to verify the three successful tasks.
  
  >**Note**: It may take over 15 minutes before the Status shows “Connected” and the graph displays Data received.

</details>

#

<details>
  
<summary>
  
### Task 3: Create a rule that uses the Azure Activity data connector
  
</summary>  

1. On the Microsoft Sentinel Configuration blade, click "Analytics".

2. On the Analytics blade, switch to the "Rule templates" tab.
  
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/f4715117-adc9-4784-b355-21e324bf8dc1" height="80%" width="80%" alt="Sentinel Analytics Rule Templates"/>
  
  >**Note**: Review the types of rules you can create. Each rule is associated with a specific Data Source. 

3. Search for "Suspicious" and select the rule template associated with the Azure Activity data source for suspicious resource creation or deployment.

4. Click "Create rule" to start creating the rule from the template.
  
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/ede2cf96-e760-48f6-91a2-43d64a08be26" height="80%" width="80%" alt="Create Analytics Rule"/>

5. Configure the rule settings on the General, Set rule logic, Incident settings, and Automated response tabs as per the default settings.
  
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/c0792160-2e51-43d8-b0f9-5977cadd4883" height="50%" width="50%" alt="Create a New Rule from Template (General Tab)"/>
 
Rule Logic Defaults
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/017964c3-1509-4a87-968e-f3842bd0ad31" height="80%" width="80%" alt="Analytics rule wizard - Set Logic Rules from Template"/>
 
<details>
  
 <summary> Set Logic Rule in Template </summary>
  
```kql 
let szOperationNames = dynamic(["microsoft.compute/virtualMachines/write", "microsoft.resources/deployments/write"]);
let starttime = 7d;
let endtime = 1d;
let timeframe = 1d;
let TimeSeriesData =
AzureActivity
| where TimeGenerated between (startofday(ago(starttime)) .. startofday(now()))
| where OperationNameValue in~ (szOperationNames)
| project TimeGenerated, Caller 
| make-series Total = count() on TimeGenerated from startofday(ago(starttime)) to startofday(now()) step timeframe by Caller; 
TimeSeriesData
| extend (anomalies, score, baseline) = series_decompose_anomalies(Total, 3, -1, 'linefit')
| mv-expand Total to typeof(double), TimeGenerated to typeof(datetime), anomalies to typeof(double), score to typeof(double), baseline to typeof(long) 
| where TimeGenerated >= startofday(ago(endtime))
| where anomalies > 0 and baseline > 0
| project Caller, TimeGenerated, Total, baseline, anomalies, score
| join (AzureActivity
| where TimeGenerated > startofday(ago(endtime)) 
| where OperationNameValue in~ (szOperationNames)
| summarize make_set(OperationNameValue,100), make_set(_ResourceId,100), make_set(CallerIpAddress,100) by bin(TimeGenerated, timeframe), Caller
) on TimeGenerated, Caller
| mv-expand CallerIpAddress=set_CallerIpAddress
| project-away Caller1
| extend Name = iif(Caller has '@',tostring(split(Caller,'@',0)[0]),"")
| extend UPNSuffix = iif(Caller has '@',tostring(split(Caller,'@',1)[0]),"")
| extend AadUserId = iif(Caller !has '@',Caller,"")
``` 
 </details> 
  

6. Review the rule configuration and click "Create" to activate the rule.
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/31209b32-50a8-4ee2-9f50-9ad2f716891a" height="80%" width="80%" alt="Validation of Analytics Rule from Template"/>

  >**Note**: You now have an active rule. 

</details>

#

<details>
  
<summary>
  
### Task 4: Create a playbook
  
</summary>  

1. In the Azure portal, search for "Deploy a custom template" in the Search resources, services, and docs text box.

2. On the Custom deployment blade, choose the option to build your own template in the editor.
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/e41a95de-a5b9-4468-af6a-2c779f0e5bb0" height="50%" width="50%" alt="Build a Template for Custom Template"/> 

3. Load the provided template file "changeincidentseverity.json" [here](https://github.com/0xbythesecond/Microsoft-Sentinel/blob/main/changeincidentseverity.json).
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/22935ac3-05d5-4687-829c-f0a178281f45" height="70%" width="70%" alt="Load JSON Template"/>

4. Save the template and provide the necessary details such as subscription, resource group, location, playbook name, and user name.

5. Review the settings and click "Review + create" and then "Create" to deploy the playbook.
 
 <img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/959f371a-d168-43de-9a61-c10a4da99547" height="50%" width="50%" alt="Create The Template and Select the Resource Group"/>
 
 >**Note**: Wait for the deployment to complete.

In the Azure portal, in the Search resources, services, and docs text box at the top of the Azure portal page, type Resource groups and press the Enter key.

On the Resource groups blade, in the list of resource group, click the AZ500LAB131415 entry.

On the AZ500LAB131415 resource group blade, in the list of resources, click the entry representing the newly created Change-Incident-Severity logic app.

On the Change-Incident-Severity blade, click Edit.

  >**Note**: On the Logic Apps Designer blade, each of the four connections displays a warning. This means that each needs to reviewed and configured.

On the Logic Apps Designer blade, click the first Connections step.
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/35deb285-f852-4fa9-9b28-6c8ae9c87f4d" height="70%" width="70%" alt="Add New Connection"/> 

Click Add new, ensure that the entry in the Tenant drop down list contains your Azure AD tenant name and click Sign-in.
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/24058bca-5568-4e57-887e-a5bc23f39c7a" height="50%" width="50%" alt="Select Default Directory"/> 

When prompted, sign in with the user account that has the Owner or Contributor role in the Azure subscription you are using for this lab.

Click the second Connection step and, in the list of connections, select the second entry, representing the connection you created in the previous step.

Repeat the previous steps in for the remaining two Connection steps.
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/d9c27651-32e6-4105-bdff-68e3afd2acf5" Lheight="70%" width="70%" alt="Logic Apps Designer - Microsoft Azure"/> 

  >**Note**: Ensure there are no warnings displayed on any of the steps.

On the Logic Apps Designer blade, click Save to save your changes.


</details>

#

<details>
  
<summary>
  
### Task 5: Create a custom alert and configure a playbook as an automated response
  
</summary>  

1. Go to the Microsoft Sentinel Overview blade and click "Analytics" in the Configuration section.

2. On the Analytics blade, click "+ Create" and select "Scheduled query rule" from the drop-down menu.
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/85b4fdcf-8c97-4642-93ed-4ee53c518540" height="70%" width="70%" alt="Create Scheduled Query Rule"/>

3. On the General tab of the Create new rule blade, specify the rule name, tactics, and other settings.
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/e14c2936-f617-4de0-853d-c1bcc15d2a50" height="70%" width="70%" alt="Create a New Scheduled Rule (General Tab)"/>

4. Switch to the Set rule logic tab and paste the provided rule query in the Rule query text box.
 
```kql
 AzureActivity
  | where ResourceProviderValue =~ "Microsoft.Security" 
  | where OperationNameValue =~ "Microsoft.Security/locations/jitNetworkAccessPolicies/delete" 
``` 
 
   >**Note**: This rule identifies removal of Just in time VM access policies.

  >**Note**: if you receive a parse error, intellisense may have added values to your query. Ensure the query matches otherwise paste the query into notepad and then from notepad to the rule query.

5. Configure the query scheduling and other settings as per the instructions.

6. On the Automated response tab, select the checkbox next to the Change-Incident-Severity playbook in the Alert automation (classic) dropdown list.
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/cf2d9e47-ad59-4982-9cfd-05a4748239ef" height="70%" width="70%" alt="Create Sentinel Analytics Rule - (Automation Rule Tab)"/>

7. Review the settings and click "Create" to activate the rule.
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/e695338d-bac6-4968-9c3c-5516569442f9" height="70%" width="70%" alt="Create a New Scheduled Rule (Review Create)"/> 
 
  >**Note**: You now have a new active rule called Playbook Demo. If an event identified by the rue logic occurs, it will result in a medium severity alert, which will generate a corresponding incident.

</details>

#

<details> 
  
<summary>
  
### Task 6: Invoke an incident and review the associated actions
  
</summary>

1. Open the Azure portal and navigate to the "Microsoft Defender for Cloud | Overview" blade.

2. Verify your secure score, which should have been updated by now.

3. Go to the "Microsoft Defender for Cloud | Workload protections" blade.

4. Under the "Advanced protection" section, click on "Just-in-time VM access."

5. On the "Microsoft Defender for Cloud | Just in time VM access" blade, locate the row corresponding to the target virtual machine (e.g., myVM).

6. Click the ellipses button on the right-hand side of the row, select "Remove," and confirm by clicking "Yes."
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/9bdecc25-850a-40f1-98e5-fb7c6f07840d" height="70%" width="70%" alt="Remove JIT VM Access"/>

  >**Note**: If the VM is not listed in the "Just-in-time VMs," go to the "Virtual Machine" blade, click on "Configuration," enable the "Just-in-time VMs" option under the Just-in-time VM's access, and repeat the previous step after navigating back to the "Microsoft Defender for Cloud" blade.

7. In the Azure portal, use the search box at the top to type "Activity log" and press Enter.

8. Navigate to the "Activity log" blade and look for an entry indicating the deletion of JIT Network Access Policies. Please note that it may take a minute to appear.
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/e19c4ad9-54d0-4695-b3ed-498884987340" height="70%" width="70%" alt="Activity Log Displays Delete JIT Network Access Policies"/> 

9. Go back to the Azure portal and navigate to the "Microsoft Sentinel | Overview" blade.

10. Review the dashboard on the "Microsoft Sentinel | Overview" blade and verify if it displays an alert corresponding to the deletion of the Just-in-time VM access policy.

  >**Note**: It may take up to 5 minutes for alerts to appear. If you don't see an alert, run the query rule mentioned in the previous task to check if the Just-in-Time access policy deletion activity has been propagated to the Log Analytics workspace associated with your Microsoft Sentinel instance. If not, recreate the Just-in-time VM access policy and repeat the deletion step.

11. In the "Threat Management" section of the "Microsoft Sentinel | Overview" blade, click on "Incidents."

12. Verify that the "Incidents" blade displays an incident with either medium or high severity level.
 
<img src="https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/21448a5d-dc55-463c-9d69-2f280ac9bc62" height="70%" width="70%" alt="Created Incidents"/>

  >**Note**: It may take up to 5 minutes for the incident to appear on the "Microsoft Sentinel | Incidents" blade.

13. Take a look at the "Microsoft Sentinel | Playbooks" blade to see the count of successful and failed playbook runs.

  >**Note**: You have the option to assign a different severity level and status to an incident.

 >Results: You have successfully simulated an incident by removing a Just-in-Time VM access policy. You have also reviewed the associated alerts and incidents in Microsoft Sentinel. This exercise confirms that you have created a Microsoft Sentinel workspace, connected it to Azure Activity logs, created a playbook, and set up custom alerts triggered by the removal of Just-in-Time VM access policies. You have validated the configuration.

Clean up resources:

Remember to remove any Azure resources that are no longer needed to avoid unexpected costs.

1. In the Azure portal, click the first icon in the top right to open the Cloud Shell.

2. If prompted, select PowerShell and create storage.

3. Ensure that PowerShell is selected in the drop-down menu in the upper-left corner of the Cloud Shell pane.

4. Run the following command in the PowerShell session within the Cloud Shell pane to remove the resource group created in this lab:

```powershell
Remove-AzResourceGroup -Name "AZ500LAB131415" -Force -AsJob
```

![Delete Resource Group](https://github.com/0xbythesecond/Microsoft-Sentinel/assets/23303634/1c815e83-ebbf-4863-a519-854ad805b048)
 
 
5. Close the Cloud Shell pane.
  
</details>  

## Reflection
In this lab, I successfully completed the on-boarding and configuration of Microsoft Sentinel in Azure. I followed a step-by-step process to connect the Log Analytics workspace and configure the Azure Activity data connector. I also created a rule that utilizes the Azure Activity data connector and set up a playbook for automated response. Additionally, I created a custom alert and associated it with the playbook. Finally, I invoked an incident and reviewed the actions taken by Microsoft Sentinel. Overall, this lab provided hands-on experience in setting up Azure Sentinel and leveraging its capabilities for threat detection and response.

## Closing
By completing this lab, I have gained practical knowledge in on-boarding Azure Sentinel and configuring its essential components. Azure Sentinel offers powerful capabilities for security monitoring and response, and this lab has equipped us with the skills to leverage its features effectively. I've learned how to connect data sources, create rules, set up automated responses, and review incidents. This knowledge will be valuable in enhancing our organization's security posture and strengthening our ability to detect and respond to threats effectively.
