# All is well so signal success
/opt/aws/bin/cfn-signal -e 0 --stack {AWS::StackName} --resource %%RESOURCE%%   --region {AWS::Region}
