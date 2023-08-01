import requests, re, sys, os
import pandas as pd
import numpy as np
from datetime import datetime
import openpyxl as openpyxl
pd.options.mode.chained_assignment = None  # default='warn'
date_today = datetime.today()



#########################################################
################### Filename input ######################
#########################################################

source_file = 'sample input.txt'
destination_file = f'Threatbook responses {date_today.strftime("%d-%m-%Y")}.xlsx'





########################################### DO NOT TOUCH all THE CODE BELOW ###########################################

#########################################################
############### Data ingestion & preparation ############
#########################################################

# read in ip addresses from .txt file
with open(source_file,'r') as file:    
    resources = file.read().splitlines()
    original_len = len(resources)


apikey_collection = ['91f535c9c678428ea29864f04f2a147532883c41a85444898a0eb00df91f589c'] #CSY premium key

total_apikeys = len(apikey_collection)




#####################################################
####### Functions to check the type of input  #######
#####################################################

url_for_IP =  'https://api.threatbook.io/v1/ip/query?apikey='
url_for_domain = 'https://api.threatbook.io/v1/domain/query?apikey='


def get_input_type(input_string):
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', input_string):  # IP address pattern
        return 'ipv4'
    elif re.match(r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$', input_string):  # Domain pattern
        return 'domain'
    else:
        return 'Unknown'

def get_threatbook_url(input_type, apikey):
    if input_type == 'ipv4':
        return url_for_IP + apikey
    elif input_type == 'domain':
        return url_for_domain + apikey
    else:
        return None
    
def input_string_id(dict,resource):
    dict['id'] = resource
    return dict

def label_input_type(dict, input_type):
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

def input_not_valid(resource,count):
    print(f'processing input {count}: \033[33m{resource}\033[0m')
    print('\033[31mprocess failed: cannot process input that is not an IP or domain\033[0m',"\n")

class BreakLoopException(Exception):
    pass



#########################################################
################ virusTotal processing ##################
#########################################################

# process each IP in ThreatBook
row_arr = []
count = 0; count_api=0; not_processed_count = 0
error_list = []
headers = {"accept": "application/json"}
break_now = False


for apikey in apikey_collection:

    # if all inputs have been processed
    if len(resources) == 0: break
    
    # Current API used
    count_api += 1
    print(f'Now using API key {count_api}: \033[34m{apikey}\033[0m',"\n")


    while len(resources) > 0: 
        
        ####################################
        # Process each input in while loop #
        ####################################

        # if all inputs have been processed
        if len(resources) == 0: break

        # Get the first input in source file
        resource = resources[0]


        try:
            #################################################
            # Identify the corrent input_type & get response #
            #################################################

            input_type = get_input_type(resource)
            threatbook_url = get_threatbook_url(input_type,apikey)
            parameters = {'apikey': apikey, 'resource': resource}

            # To print the type of input
            if threatbook_url:
                print(f"input type: {input_type}")
            else:
                count += 1
                input_not_valid(resource,count)
                resources.pop(0)
                not_processed_count += 1
                continue

            # Get result from Threatbook
            threatbook_url_ = threatbook_url + '&resource=' + resource
            response = requests.get(threatbook_url_, headers=headers).json()


            #########################################
            # Check if ThreatBook quota is exceeded #
            #########################################
            
            if (response['msg'] == 'Beyond daily quotas limitation'):
                print("\033[34mQuota for this API-key has been exceeded. Switch to next api-key.\033[0m")
                print(f'\033[34mNumber of api-keys used: {count_api}/{total_apikeys}\033[0m')
                break #skip to next api-key


            ##########################################
            # If quota is enough for current api-key #
            ##########################################

            # To count the number of inputs
            count += 1

            print(f'processing input {count}: \033[33m{resource}\033[0m')

            # Remove the resource input from the resources list
            resources.pop(0)


            ##################
            # Error handling #
            ##################

            if(response['msg'] != 'Success'):
                print(response,"\n"); 
                if(response['msg'] == 'No access to API'): 
                    print('\033[31mAPI-key must be a premium API\033[0m')
                raise BreakLoopException('\033[31mPlease rectify the error.\033[0m')
            
            if('first_seen' not in response['data']['summary']): 
               nested_dict =   response['data']['summary']
               nested_dict['first_seen'] = '-'


            if('last_seen' not in response['data']['summary']): 
                nested_dict =   response['data']['summary']
                nested_dict['last_seen'] = '-'


        except Exception as e:
            print(); print(f'\033[31mexception: {e}\033[0m')
            continue

        else:
            # put the input string into each response
            response = input_string_id(response, resource)
            
            # For each input, label it as IP,domain, or hash
            response = label_input_type(response,input_type)
            row_arr.append(response)
            print()
    print()


# Convert json file into pandas dataframe
df = pd.json_normalize(row_arr)




###############################################################
########### Check if source file is fully processed ###########
###############################################################

print('____________________________________________________________________________________________________')

# to remove those inputs that cannot be processed. Eg headers or empty lines
count = count - not_processed_count
original_len = original_len - not_processed_count
filename_ = generate_unique_filename(destination_file)

# Check the cut_off point
if(original_len == count): 
    print(f'\033[32mThreatbook quota is sufficient.\033[0m')
    print(f'\033[32mWhole input file has been fully processed and saved as {filename_}\033[0m'); print()
else:
    count_ = count + 1
    print(f'\033[31mThe input file is not fully processed. Due to the lack of API-keys or an error.\033[0m')
    if count != 0: print(f'\033[31mThe input file is processed until input {resource} in line {count}.\033[0m')
    print(f'\033[31mA separate batch starting from line {count_} is needed.\033[0m'); print()

# If there's nothing in the df
if(len(df) == 0): sys.exit()




#########################################################
##################### Data Cleaning #####################
#########################################################

# Specify columns to keep
df.rename(columns = {'data.summary.whitelist': 'Whitelist',
                     'data.summary.first_seen': 'first_seen (first discovery of intelligence)',
                     'data.summary.last_seen': 'last_seen (last discovery of intelligence)',
                     'label': 'Type',
                     'id': 'Input'
                     }, inplace=True)



df['Days from last_seen'] = ''
df1 = df[['Input','Type','first_seen (first discovery of intelligence)','last_seen (last discovery of intelligence)','Days from last_seen','Whitelist']]

# Data transformation for date
df1['last_seen (last discovery of intelligence)'] = df1['last_seen (last discovery of intelligence)'].replace([np.inf, -np.inf], np.nan)  # Replace inf values with NaN                                    df1['Last analysis date'])


def clean_date(date):
    if date != "-":
        date = pd.to_datetime(date, unit='s', errors='coerce').date()
    return date


df1['last_seen (last discovery of intelligence)'].number_format = 'dd-mm-yyyy'
df1['last_seen (last discovery of intelligence)'].fillna('-', inplace=True)




#########################################################
############# Check if input is malicious   #############
#########################################################

def calculate_malicious_safe(row):
    whitelist = row['Whitelist']
    if whitelist == False :
        return 'Malicious'
    elif whitelist == True:
        return 'Safe'
    else:
        return 'Not Found'

mal = df1['Whitelist']

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
sheet['C1'].number_format = 'dd-mm-yyyy'
sheet['C1'].alignment = openpyxl.styles.Alignment(horizontal='left')

sheet['B2'] = 'Today\'s date:'
sheet['C2'] = '=TODAY()'

# Apply date formatting to the cell
sheet['C2'].number_format = 'dd-mm-yyyy'
sheet['C2'].alignment = openpyxl.styles.Alignment(horizontal='left')

# Calculate the "Days from today" column 
end_row = len(df1.index)  # Number of rows to fill

for row in range(5, end_row + num_rows_to_insert +  2):
    if(sheet[f'E{row}'].value == '-'):
         sheet[f'F{row}'] = '-'
    else:
        sheet[f'F{row}'] = f'=$C$2-E{row}'

    sheet[f'F{row}'].alignment = openpyxl.styles.Alignment(horizontal='right')

# Save excel file
workbook.save(filename = filename_)




#########################################################
################## Print Exceptions #####################
#########################################################

print('\033[32m##### Summary #####\033[0m')
print(f'\033[32mNumber of inputs in source_file: {original_len + not_processed_count}\033[0m')
print(f'\033[32mNumber of inputs processed: {count}\033[0m')
print(f'\033[32mNumber of inputs not processed due to invalid input: {not_processed_count}\033[0m')
print(f'\033[32mNumber of api-keys used: {count_api}/{total_apikeys}\033[0m')
print('*invalid inputs includes inputs that are not of IP. Eg, domains, hash, blank lines, etc',"\n")

if(error_list):
    print('Here are a list of inputs that were not read. These might be headers, or Invalid Arguments that cannot be read by virusTotal')
    for element in error_list:
        print(f'\033[33m{element}\033[0m'); 