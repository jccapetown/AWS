#Author: Jacques Coetzee
#Summary: Run this against your AWS environment to detect Security Groups and possible firewall misconfigurations
#You need to set your secret key and access key in your environment variables
#Written in python 3

import boto3

class Struct:
    def __init__(self, **entries):
        self.__dict__.update(entries)

#dictionary to hold our security groups
SG = {}

#lets get the current security groups in aws for the default region
ec2 = boto3.client('ec2')

response = ec2.describe_security_groups()
for sg in response['SecurityGroups']:
   #print(sg)
   groupinfo = Struct(**sg)
   description = groupinfo.Description
   name = groupinfo.GroupName
   id = groupinfo.GroupId

     
   #set up the variables
   SG[name] = {}
   SG[name]['Description'] = description
   SG[name]['GroupId'] = id
   SG[name]['Ingress'] = {} 
   SG[name]['Egress'] = {}
   #Loop though the ingress rules 
   ingressruleno = 0
   for IngressRule in groupinfo.IpPermissions:
       ingressruleno += 1;
       perms = Struct(**IngressRule);
       
       if perms.IpProtocol == '-1':
           perms.IpProtocol = 'All'

       SG[name]['Ingress'][ingressruleno] = {}
       SG[name]['Ingress'][ingressruleno]['proto'] = perms.IpProtocol
       SG[name]['Ingress'][ingressruleno]['sources'] = []
                   
       
       try:
          SG[name]['Ingress'][ingressruleno]['port'] = perms.FromPort
          for source in perms.IpRanges:
             SG[name]['Ingress'][ingressruleno]['sources'].append(source['CidrIp'])       
       except Exception as e:
           SG[name]['Ingress'][ingressruleno]['port'] = 'All'
           SG[name]['Ingress'][ingressruleno]['sources'].append('0.0.0.0/0')
           pass

   egressruleno = 0
   for EgressRule in groupinfo.IpPermissionsEgress:
       egressruleno += 1;
       perms = Struct(**EgressRule);
       #print(EgressRule)
       if perms.IpProtocol == '-1':
           perms.IpProtocol = 'All'
           
       SG[name]['Egress'][egressruleno] = {}
       SG[name]['Egress'][egressruleno]['proto'] = perms.IpProtocol
       SG[name]['Egress'][egressruleno]['dest'] = []
       
       try:
          SG[name]['Egress'][egressruleno]['port'] = perms.ToPort
          for dest in perms.IpRanges:
            SG[name]['Egress'][egressruleno]['dest'].append(dest['CidrIp'])
       except Exception as e:
           SG[name]['Egress'][egressruleno]['port'] = 'All'
           SG[name]['Egress'][egressruleno]['dest'].append('0.0.0.0/0')
           pass

        
#print the output
for securitygroup in SG:
   sg = Struct(**SG[securitygroup])
   rowmax = 68
   col1 = 12
   col2 = 7
   col3 = 11
   col4 = 19
   print('*' * rowmax);
   print('*');
   print('*', 'Security Group Name:',securitygroup)
   print('*', 'Description:        ', sg.Description[:43])
   print('*', 'Id:                 ', sg.GroupId)
   #print('*');
   
   print('*',' ________________________________________________________________');
   print('*','| Direction     | Port     | Protocol     | IP/CIDR              |');
   print('*','| ---------     | ----     | --------     | -------              |');
   for index in sg.Ingress:
     rule = Struct(**sg.Ingress[index])
     for iprange in rule.sources:
         
         print('*','|','-> Ingress',' '*(col1-len('-> Ingress')), '|',
               rule.port, ' '*(col2-len(str(rule.port))), '|',
               rule.proto, ' '*(col3-len(str(rule.proto))), '|',
               iprange, ' '*(col4-len(str(iprange))), '|',
           ) 
   for index in sg.Egress:
     rule = Struct(**sg.Egress[index])
     for iprange in rule.dest:
         
         print('*','|','<- Egress',' '*(col1-len('<- Egress')), '|',
               rule.port, ' '*(col2-len(str(rule.port))), '|',
               rule.proto, ' '*(col3-len(str(rule.proto))), '|',
               iprange, ' '*(col4-len(str(iprange))), '|',
           )
   
   print('*','|________________________________________________________________|');
   print('*');
