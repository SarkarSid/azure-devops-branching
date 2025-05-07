Azure DevOps Repository Policy Management
A streamlined PowerShell solution for automating Azure DevOps repository configuration with standard branch security and policy settings.

Purpose
This project automates setting up branch security and repository policies for Azure DevOps repositories, ensuring consistent branch protection practices across your organization.

What it Does
✅ Enforces code review policies with 2 minimum approvers
✅ Prevents force-pushes to protected branches
✅ Requires work items to be linked for traceability
✅ Resets approvals when new changes are pushed
✅ Sets proper security boundaries for contributors/readers
✅ Requires comments for pull request completion

Getting Started
Configure Azure DevOps PAT with appropriate permissions:

Code (Read, Write, Manage)
Security (Read, Manage)
Work Items (Read)
Run the script through Azure Pipelines or directly:

Azure Pipeline Integration
Use the included pipeline template to automate policy application across repos:
parameters:
  - name: repositoryName
    type: string
    default: 'MyRepo'

trigger: none

extends:
  template: azure-pipeline-template.yml
  parameters:
    organizationUrl: 'https://dev.azure.com/yourorg'
    projectName: 'YourProject'
    repositoryName: ${{ parameters.repositoryName }}


Common Issues and Solutions
Failed API Calls: Ensure PAT has sufficient permissions
Permission Denied: API calls require Code and Security permissions
Token Errors: PAT may be expired or malformed
Customization
Modify policy settings in the Set-RepositoryPolicies function to match your organization's requirements.

-------Demo Purpose Only By: Sid-----------------------







Ref: Microsoft/Azure/VS tooling
