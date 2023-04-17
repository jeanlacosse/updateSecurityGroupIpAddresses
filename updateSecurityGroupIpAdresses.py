import os
import boto3
import requests

# to invoke this from API gateway, from local machine in order to get that machines actual IP address, use the local script in powershell to invoke 
# this any time I need to update my ip addresses in my security groups.

# Update security group rules
def update_security_group(sg_id, old_ip, new_ip, port):
    ec2 = boto3.client('ec2')

    print('revoking old ip')
    # Revoke old IP
    ec2.revoke_security_group_ingress(
        GroupId=sg_id,
        IpProtocol='tcp',
        FromPort=port,
        ToPort=port,
        CidrIp=f'{old_ip}/32'
    )

    print('adding new ip')
    # Add new IP
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpProtocol='tcp',
        FromPort=port,
        ToPort=port,
        CidrIp=f'{new_ip}/32'
    )

def lambda_handler(event, context):
    SECURITY_GROUP_IDS = os.environ['SECURITY_GROUP_IDS'].split(',')
    print('SECURITY_GROUP_IDS are:', SECURITY_GROUP_IDS)
    PORTS = os.environ['PORTS'].split(',')
    print('PORTS are:', PORTS)
    current_ip = event['ip_address']

    print('Current ip address is:', current_ip)

    ec2 = boto3.client('ec2')
    print('ec2 client created with boto3')
    security_groups = ec2.describe_security_groups(GroupIds=SECURITY_GROUP_IDS)

    for security_group in security_groups['SecurityGroups']:
        sg_id = security_group['GroupId']
        ingress_rules = security_group['IpPermissions']

        for port in PORTS:
            for rule in ingress_rules:
                if rule['FromPort'] == int(port) and rule['ToPort'] == int(port):
                    print('length of ip ranges:', len(rule['IpRanges']))
                    old_ip = rule['IpRanges'][0]['CidrIp'].split('/')[0] if len(rule['IpRanges']) > 0 else None
                    # code is breaking here
                    if old_ip and old_ip != current_ip:
                        update_security_group(sg_id, old_ip, current_ip, int(port))
                        print(f'Updated security group {sg_id} for port {port} with new IP: {current_ip}')
                        break

