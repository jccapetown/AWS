#Author: Jacques Coetzee
#Summary: Run this against your AWS environment to detect S3 buckets that may be publicly accessible
#You need to set your secret key and access key in your environment variables
#Written in python 3

import boto3
#initialise a client to the s3 service
client = boto3.client('s3')

class Struct:
    def __init__(self, **entries):
        self.__dict__.update(entries)



#lets get the current buckets
response = client.list_buckets()
print("Inspecting Buckets for signs off Public access")
print("")

for bucket in response['Buckets']:
    #print(bucket)
    s = Struct(**bucket)
    print(f' -- Inspecting bucket: {s.Name} -- ')
    bucketOpenToWorld = False

    #Check the ACL for known bucket groups indicating public access
    response_acl = client.get_bucket_acl(Bucket=bucket['Name'])

    for grant in response_acl['Grants']:
        #print(grant)
        uri = None
        displayname = grant['Grantee']['DisplayName']
        print(f'Grantee: {displayname}') 

        tipe = grant['Grantee']['Type']
        print(f'Type: {tipe}') 

        if tipe == 'Group':
            uri = grant['Grantee']['URI']
            print(f'URI: {uri}') 

            if 'authenticatedusers' in lower(uri):
                print(' * Found the Group AuthenticatedUsers - This Bucket may be public')
                bucketOpenToWorld = True

            if 'allusers' in lower(uri):
                print(' * Found the Group AllUsers - This Bucket may be public')
                bucketOpenToWorld = True

    #Get the bucket Policies if any and check the status
    try:
        response_policy = client.get_bucket_policy_status(Bucket=bucket['Name'])
        ispublic = response_policy['PolicyStatus']['IsPublic']

        if ispublic:
            print(f"Policy Status: *Warning - Policy status is Public")
            print(' * Found the Bucket policy to be Public. Very certain this bucket is public')
            bucketOpenToWorld = True
        else:
            print(f"Policy Status: Not Public")
    except:
        #there is no policy
        print(" * Warning - Bucket Policy: There is no bucket policy set.")
        print(" * A bucket policy can set the bucket to disallow public access detectable through the 'IsPublic' attribute")        
        pass

    

    #See if the public access blocking policies exist
    try:
        response_access_block = client.get_public_access_block(Bucket=bucket['Name'])
        BlockPublicACLS = response_access_block['PublicAccessBlockConfiguration']['BlockPublicAcls']
        BlockPublicPolicy = response_access_block['PublicAccessBlockConfiguration']['BlockPublicPolicy']

        if (not BlockPublicACLS) and (not BlockPublicPolicy):
            print(f"BlockPublic Config :")
            print(f" * BlockPublicACLS is set to {BlockPublicACLS}")
            print(f" * BlockPublicPolicy is set to {BlockPublicPolicy}")
            print(f" * Warning - If both configs arent set to true, the bucket is very likely to be public")
        else:
            bucketOpenToWorld = False

    except:
        print(" * Warning - Public access block configuration not Set. ")
        print(" * If the BlockPublicAcls and BlockPublicPoliciy is net both set to true, the Bucket may be public.")
        pass



    print("")
    print(f"In Summary, do we believe that this bucket is publicly accessible?")
    print(f"Our answer is {bucketOpenToWorld}") 
    print('')
    print('')

