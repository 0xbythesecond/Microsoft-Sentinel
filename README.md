# Microsoft Sentinel

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

Task 2: Connect Azure Activity to Sentinel

1. On the Microsoft Sentinel blade, go to the Configuration section and click "Data connectors".

2. On the Data connectors blade, search for "Azure" and select the Azure Activity data connector.

3. On the Azure Activity blade, follow the instructions to configure the connector. This includes connecting your subscriptions through diagnostic settings using the Azure Policy Assignment wizard.

4. Review and confirm the successful configuration of the Azure Activity data connector.

</details>

#

<details>
  
<summary>
  
### Task 3: Create a rule that uses the Azure Activity data connector
  
</summary>  

1. On the Microsoft Sentinel Configuration blade, click "Analytics".

2. On the Analytics blade, switch to the "Rule templates" tab.

3. Search for "Suspicious" and select the rule template associated with the Azure Activity data source for suspicious resource creation or deployment.

4. Click "Create rule" to start creating the rule from the template.

5. Configure the rule settings on the General, Set rule logic, Incident settings, and Automated response tabs as per the default settings.

6. Review the rule configuration and click "Create" to activate the rule.

</details>

#

<details>
  
<summary>
  
### Task 4: Create a playbook
  
</summary>  

1. In the Azure portal, search for "Deploy a custom template" in the Search resources, services, and docs text box.

2. On the Custom deployment blade, choose the option to build your own template in the editor.

3. Load the provided template file "changeincidentseverity.json" from the \Allfiles\Labs\15\ directory.

4. Save the template and provide the necessary details such as subscription, resource group, location, playbook name, and user name.

5. Review the settings and click "Review + create" and then "Create" to deploy the playbook.

</details>

#

<details>
  
<summary>
  
### Task 5: Create a custom alert and configure a playbook as an automated response
  
</summary>  

1. Go to the Microsoft Sentinel Overview blade and click "Analytics" in the Configuration section.

2. On the Analytics blade, click "+ Create" and select "Scheduled query rule" from the drop-down menu.

3. On the General tab of the Create new rule blade, specify the rule name, tactics, and other settings.

4. Switch to the Set rule logic tab and paste the provided rule query in the Rule query text box.

5. Configure the query scheduling and other settings as per the instructions.

6. On the Automated response tab, select the checkbox next to the Change-Incident-Severity playbook in the Alert automation (classic) dropdown list.

7. Review the settings and click "Create" to activate the rule.

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

  >**Note**: If the VM is not listed in the "Just-in-time VMs," go to the "Virtual Machine" blade, click on "Configuration," enable the "Just-in-time VMs" option under the Just-in-time VM's access, and repeat the previous step after navigating back to the "Microsoft Defender for Cloud" blade.

7. In the Azure portal, use the search box at the top to type "Activity log" and press Enter.

8. Navigate to the "Activity log" blade and look for an entry indicating the deletion of JIT Network Access Policies. Please note that it may take a minute to appear.

9. Go back to the Azure portal and navigate to the "Microsoft Sentinel | Overview" blade.

10. Review the dashboard on the "Microsoft Sentinel | Overview" blade and verify if it displays an alert corresponding to the deletion of the Just-in-time VM access policy.

  >**Note**: It may take up to 5 minutes for alerts to appear. If you don't see an alert, run the query rule mentioned in the previous task to check if the Just-in-Time access policy deletion activity has been propagated to the Log Analytics workspace associated with your Microsoft Sentinel instance. If not, recreate the Just-in-time VM access policy and repeat the deletion step.

11. In the "Threat Management" section of the "Microsoft Sentinel | Overview" blade, click on "Incidents."

12. Verify that the "Incidents" blade displays an incident with either medium or high severity level.

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

5. Close the Cloud Shell pane.
  
</details>  
