import requests, re, sys, os
import pandas as pd
import numpy as np
from datetime import datetime
import openpyxl as openpyxl
pd.options.mode.chained_assignment = None 
date_today = datetime.today()


#########################################################
################### Filename input ######################
#########################################################

source_file = 'sample_input.txt'
destination_file = f'VirusTotal_responses_{date_today.strftime("%d-%m-%Y")}.xlsx'





########################################### DO NOT TOUCH THE CODE BELOW ###########################################

#########################################################
############### Data ingestion & preparation ############
#########################################################

# read in ip addresses from .txt file
with open(source_file,'r') as file:    
    resources = file.read().splitlines()
    original_len = len(resources)


apikey_collection = ['apikey1', 'apikey2', 'apikey3'] #replace with your apikey from virusTotal

total_apikeys = len(apikey_collection)





#####################################################
####### Functions to check the type of input  #######
#####################################################

# URL for different types of inputs
url_for_IP =  'https://www.virustotal.com/api/v3/ip_addresses/'
url_for_domain = 'https://www.virustotal.com/api/v3/domains/'
url_for_URL = 'https://www.virustotal.com/api/v3/urls/'
url_for_hash = 'https://www.virustotal.com/api/v3/files/'


def get_input_type(input_string):
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', input_string):  # IP address pattern
        return 'ipv4'
    elif re.match(r'^[a-fA-F0-9]{32}$', input_string):  # MD5 hash pattern
        return 'md5'
    elif re.match(r'^[a-fA-F0-9]{64}$', input_string):  # SHA-256 hash pattern
        return 'sha256'
    elif re.match(r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$', input_string): # Domain pattern
        return 'domain'
    elif re.match(r'^https?://', input_string):  # URL pattern
        return 'URL'
    else:
        return 'domain/invalid'

def get_virustotal_url(input_type):
    if input_type == 'ipv4':
        return 'https://www.virustotal.com/api/v3/ip_addresses/'
    elif (input_type == 'md5') | (input_type == 'sha256'):
        return 'https://www.virustotal.com/api/v3/files/'
    elif (input_type == 'domain') or (input_type == 'domain/invalid'):
        return 'https://www.virustotal.com/api/v3/domains/'
    elif input_type == 'URL':
        return 'https://www.virustotal.com/api/v3/urls/'

def input_string_id(dict,resource):
    dict['id'] = resource
    return dict

def label_input_type(dict, input_type):
    if input_type == 'Unknown':
        dict['label'] = 'Unknown'
    else:
        dict['label'] = input_type
    return dict

def generate_unique_filename(base_filename):
    filename = f"{base_filename}"
    counter = 1

    while os.path.exists(filename):
        if base_filename.endswith('.xlsx'):
            base_filename = base_filename[:-5]

        filename = f"{base_filename} ({counter}).xlsx"
        counter += 1

    return filename





#########################################################
################ virusTotal processing ##################
#########################################################

# process each IP in virusTotal
row_arr = []
count = 0; count_api=0
error_list = []
temp = ''


for apikey in apikey_collection:

    # if all inputs have been processed
    if len(resources) == 0: break

    count_api += 1

    headers = {  
    'accept': 'application/json',
    'x-apikey': apikey }

    print(f'API key {count_api}:\033[34m {apikey}\033[0m'); print()


    while len(resources) > 0: 

        ####################################
        # Process each input in while loop #
        ####################################

        # if all inputs have been processed
        if len(resources) == 0: break

        resource = resources[0]

        try:
            #################################################
            # Identify the corrent input_type & get its URL #
            #################################################

            input_type = get_input_type(resource)
            virustotal_url = get_virustotal_url(input_type)
            parameters = {'resource': resource, 'response_fields': 'last_analysis_results'}


            # Get result from virustotal
            virustotal_url_ = virustotal_url +  resource
            response = requests.get(virustotal_url_, headers=headers,params=parameters).json()
            

            #########################################
            # Check if virusTotal quota is exceeded #
            #########################################

            if response.get('error', {}).get('code') == 'QuotaExceededError':
                print("\033[34mvirusTotal quota has been exceeded. Switch to next api-key.\033[0m")
                print(f'\033[34mNumber of api-keys used: {count_api}/{total_apikeys}\033[0m')
                break #skip to next api-key

            
            ##########################################
            # If quota is enough for current api-key #
            ##########################################

            count += 1
            
            if resource == '': resource = '<blank>'
            print(f'processing input {count}: \033[33m{resource}\033[0m')
            print(f"input type: {input_type}")

            # Remove the resource input from the resources list
            resources.pop(0)

            # Update the last processed input for printing of comments
            temp = resource


            ##################
            # Error handling #
            ##################

            if('error' in response): 

                if((response.get('error', {}).get('code') == 'InvalidArgumentError') or (resource == '')): #if input is invalid
                    print("'InvalidArgumentError': input is not a valid IP/domain/hash")
                    input_type = 'Invalid'
                    response = {"data": {
                                    "attributes": {
                                        "last_analysis_date": "-",
                                        "last_analysis_stats": {
                                            "harmless": "-",
                                            "malicious": "-",
                                            "suspicious": "-",
                                            "undetected":"-",
                                            "timeout": "-",},
                                            },}}
                
                elif response.get('error', {}).get('code') == 'NotFoundError': #if value have no matches
                    print("'NotFoundError': virustTotal cannot find a match for the IP/domain/hash")
                    response = {"data": {
                                    "attributes": {
                                        "last_analysis_date": "-",
                                        "last_analysis_stats": {
                                            "harmless": "-",
                                            "malicious": "-",
                                            "suspicious": "-",
                                            "undetected":"-",
                                            "timeout": "-",},
                                            },}}
                
                else:
                    error_list.append(resource)
                    print('\033[31merror is in response\033[31m')
                    print(f'\033[31m{response}\033[31m'); print()
                    continue  

            try: check_existence = response['data']['attributes']['last_analysis_date']
            except KeyError:response['data']['attributes']['last_analysis_date'] = "-"

        except Exception as e: # For other types of errors that are not in response
            print(); print(f'\033[31mexception: {e}\033[0m',"\n")
            continue

        else:
            # put the input string into each response
            response = input_string_id(response, resource)
            
            # For each input, label it as IP,domain, or hash
            response = label_input_type(response,input_type)
            
            row_arr.append(response); print()

    print()


# Convert json file into pandas dataframe
df = pd.json_normalize(row_arr)





###############################
###### Empty df handling ######
###############################

filename_ = generate_unique_filename(destination_file)

# To determine next line in new file batch
count_ = count + 1

# Skip data cleaning if there's no data in df.
if len(df) == 0: 
    print(f'\033[31mDue to the lack of API-keys, the input file is not processed at all.\033[0m')
    print(f'A new batch starting from line {count_} is needed.'); print()
    sys.exit()





#########################################################
##################### Data Cleaning #####################
#########################################################

# Specify columns to keep
df.rename(columns = {'data.attributes.last_analysis_date': 'Last analysis date',
                     'data.attributes.last_analysis_stats.harmless': 'Harmless',
                     'data.attributes.last_analysis_stats.malicious': 'Malicious',
                     'data.attributes.last_analysis_stats.suspicious': 'Suspicious',
                     'data.attributes.last_analysis_stats.undetected': 'Undetected',
                     'data.attributes.last_analysis_stats.timeout': 'Timeout',
                     'label': 'Type',
                     'id': 'Input'
                     }, inplace=True)

df['Days from today'] = ''
df1 = df[['Input','Type','Last analysis date','Days from today','Harmless','Malicious','Suspicious','Undetected','Timeout']]


# Data transformation 
df1['Last analysis date'] = df1['Last analysis date'].replace([np.inf, -np.inf], np.nan)  # Replace inf values with NaN                                  

def clean_date(date):
    if date != "-":
        date = pd.to_datetime(date, unit='s', errors='coerce').date()
    return date

df1['Last analysis date'] = df1['Last analysis date'].apply(clean_date)
df1['Last analysis date'].number_format = 'dd-mm-yyyy'
df1['Last analysis date'].fillna('-', inplace=True)





#########################################################
############# Check if input is malicious   #############
#########################################################

def calculate_malicious_safe(row):
    if row['Type'] == 'Unknown':
        return '-'
    elif row['Malicious'] == '-' or row['Suspicious'] == '-':
        return 'No matches found'
    elif mal_count_list[row.name] > threshold:
        return 'Malicious'
    else:
        return 'Safe'

mal_count_list = df1['Malicious'] + df1['Suspicious']  #need to be double-checked
threshold = 0

df1['Malicious/Safe'] = df1.apply(calculate_malicious_safe, axis=1)





#########################################################
##################### Convert to Excel ##################
#########################################################

# convert to excel
date_today = datetime.today()

df1.index = np.arange(1, len(df1) + 1)
df1.to_excel(filename_,index=True)

workbook = openpyxl.load_workbook(filename_)
sheet = workbook.active

# Insert empty rows
num_rows_to_insert = 3
sheet.insert_rows(1, num_rows_to_insert)





##############################################################
##################### Add date and formula  ##################
##############################################################

# Add dates to file
sheet['B1'] = 'Date script was run:'
sheet['C1'] = date_today.date()
sheet['C1'].number_format = 'yyyy-mm-dd' #'dd-mm-yyyy'
sheet['C1'].alignment = openpyxl.styles.Alignment(horizontal='left')

sheet['B2'] = 'Today\'s date:'
sheet['C2'] = '=TODAY()'

# Apply date formatting to the cell
sheet['C2'].number_format = 'yyyy-mm-dd' 
sheet['C2'].alignment = openpyxl.styles.Alignment(horizontal='left')


# Calculate the "Days from today" column 
end_row = len(df1.index)  # Number of rows to fill

for row in range(5, end_row + num_rows_to_insert +  2):
    if(sheet[f'D{row}'].value == '-' or  sheet[f'K{row}'].value == 'No matches found'):
         sheet[f'E{row}'] = '-'
    else:
        sheet[f'E{row}'] = f'=$C$2-D{row}'

    sheet[f'E{row}'].alignment = openpyxl.styles.Alignment(horizontal='right')

sheet['K3'] = 'If (Malicious + Suspicious) > 0, then Output = \'Malicious\''


# Save excel file
workbook.save(filename = filename_)





###############################################################
########### Check if source file is fully processed ###########
###############################################################

# Check the cut_off point
if(original_len == count): 
    print(f'\033[32mThreatbook quota is sufficient.\033[0m')
    print(f'\033[32mWhole input file has been fully processed and saved as {filename_}\033[0m'); print()
else:
    if len(df):
        print(f'\033[31mDue to the lack of API-keys, the input file is processed until input \'{temp}\' in line {count}.\033[0m')
        print(f'Processed inputs are saved as {filename_}')
    else:
        print(f'\033[31mDue to the lack of API-keys, the input file is not processed at all.\033[0m')
    print(f'A new batch starting from line {count_} is needed.'); print()





###################################################################
################## Print Summary & Exceptions #####################
###################################################################

print('\033[34m###### Summary ######\033[0m')
print(f'\033[34mNumber of inputs in source file: {original_len}\033[0m')
print(f'\033[34mNumber of inputs processed: {count}\033[0m')
print(f'\033[34mNumber of api-keys used: {count_api}/{total_apikeys}\033[0m')

if(error_list):
    print('Here are a list of inputs that were not read. These might be headers, or Invalid Arguments that cannot be read by virusTotal')
    for element in error_list:
        print(f'\033[33m{element}\033[0m'); 