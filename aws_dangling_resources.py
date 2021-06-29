import boto3
from collections import defaultdict
from pprint import pprint

r53 = boto3.client('route53')
ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
dangling_resources = defaultdict()
s3_all_buckets = s3.list_buckets()
r53_zone = r53.list_hosted_zones()

def ec2_info(ipaddress,record_name):
    try:
        instance_info = ec2.describe_instances(Filters=[{
                'Name': 'ip-address',
                'Values': [ipaddress],},],)
        #Check for a value associated with an EC2 instance
        #If value doesn't exist exit the try
        exists = instance_info['Reservations'][0]['Instances'][0]['ImageId']
    except IndexError:
        dangling_resources[ipaddress] = {
            'record': ipaddress,
            'DNS': record_name
        }

def s3_info(bucketName,s3dns):
    if bucketName not in s3_all_buckets:
        dangling_resources[bucketName] = {
            'record': bucketName,
            'DNS': s3dns
        }

for zones in r53_zone['HostedZones']:
    zoneID = zones['Id'].replace('/hostedzone/', '')
    zoneName = zones['Name']
    #Get list of resources for zoneName
    r53_records = r53.list_resource_record_sets(HostedZoneId=zoneID,)
    for records in r53_records['ResourceRecordSets']:
        #Filter out non 'A' records
        if records['Type'] == 'A':
            if records.get('AliasTarget') is not None:
                #Set DNS entry for given record
                s3dns = records['AliasTarget']['DNSName']
                #Records with cloudfront indicating an S3 bucket hosting content
                if 'cloudfront' in s3dns:
                    bucketname = records['Name']
                    #Call s3_info with bucketname from associated DNS record
                    s3_info(bucketname,s3dns)
            #Filter out infrastructure hosted outside AWS, based on record name
            if records['Name'] != '[INTERNAL_RESOURCE_NAME]' + zoneName:
                try:
                    for elastic_ips in records['ResourceRecords']:
                        #Set EIP
                        ipaddr = elastic_ips['Value']
                        #Set DNS name
                        dns_name = records['Name']
                        #Filter infrastructure hosted outside AWS, based on IP
                        if '[INTERNAL_RESOURCE_IPs]' not in ipaddr:
                            #Call ec2_info with EIP and DNS name
                            ec2_info(ipaddr,dns_name)
                except KeyError:
                    continue

for records in dangling_resources:
    print(dangling_resources[records])

