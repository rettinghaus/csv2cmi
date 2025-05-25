#!/usr/bin/env python3
# csv2cmi
#
# Copyright (c) 2015-2018 Klaus Rettinghaus
# programmed by Klaus Rettinghaus
# licensed under MIT license

# needs Python3
import argparse
import configparser
import logging
import os
import random
import string
import urllib.request
from csv import DictReader
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, Comment, ElementTree

__license__ = "MIT"
__version__ = '2.0.0-alpha'

# define log output
logging.basicConfig(format='%(levelname)s: %(message)s')
logs = logging.getLogger()

# define RDF namespace
RDF_DEFAULT_NAMESPACE = {'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#'}

# In-memory cache for authority lookups
AUTHORITY_CACHE = {}

# Default configuration, to be used as fallback
DEFAULT_AUTHORITY_CONFIG = [
    {
        'id': 'viaf',
        'url_pattern': 'viaf.org', # String to check in person_id_str
        'rdf_url_suffix': '/rdf.xml',
        'type_queries': {
            'organization': './rdf:Description/rdf:type[@rdf:resource="http://schema.org/Organization"]',
            'person': './rdf:Description/rdf:type[@rdf:resource="http://schema.org/Person"]'
        },
        'namespaces': RDF_DEFAULT_NAMESPACE, # VIAF uses the default RDF namespace
        'error_message_fetch': 'Failed to reach VIAF for %sID %s in line %s',
        'error_message_parse': '%sID %s in line %s links to unprocessable VIAF authority file'
    },
    {
        'id': 'gnd',
        'url_pattern': 'd-nb.info/gnd/',
        'rdf_url_suffix': '/about/rdf',
        'type_queries': {
            # Note: ElementTree's find/findall with XPath is limited.
            # We might need to use .// for broader search or ensure paths are exact.
            # The original code used get() on a find for rdf:type, which is different.
            # This configuration assumes direct element matching.
            'organization': './/{https://d-nb.info/standards/elementset/gnd#}CorporateBody',
            'person': './/{https://d-nb.info/standards/elementset/gnd#}DifferentiatedPerson',
        },
        'person_undifferentiated_type_query': './/{https://d-nb.info/standards/elementset/gnd#}UndifferentiatedPerson',
        'namespaces': {'gndo': 'https://d-nb.info/standards/elementset/gnd#', 'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#'},
        'error_message_fetch': 'Failed to reach GND for %sID %s in line %s',
        'error_message_parse': '%sID %s in line %s has wrong rdf:type for GND or was unprocessable',
        'warning_undifferentiated': '%sID %s in line %s links to undifferentiated Person (GND)'
    },
    {
        'id': 'loc',
        'url_pattern': 'id.loc.gov',
        'rdf_url_suffix': '.rdf',
        'type_queries': {
            'organization': './/{http://id.loc.gov/ontologies/bibframe/}Organization',
            'person': './/{http://id.loc.gov/ontologies/bibframe/}Person'
        },
        'namespaces': {'bf': 'http://id.loc.gov/ontologies/bibframe/', 'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#'},
        'error_message_fetch': 'Failed to reach LOC for %sID %s in line %s',
        'error_message_parse': '%sID %s in line %s links to unprocessable LOC authority file'
    }
]

# define arguments
parser = argparse.ArgumentParser(
    description='convert tables of letters to CMI')
parser.add_argument('filename', help='input file (.csv)')
parser.add_argument('-a', '--all',
                    help='include unedited letters', action='store_true')
parser.add_argument('-n', '--notes', help='transfer notes',
                    action='store_true')
parser.add_argument('-v', '--verbose',
                    help='increase output verbosity', action='store_true')
parser.add_argument('--line-numbers',
                    help='add line numbers', action='store_true')
parser.add_argument('--version', action='version',
                    version='%(prog)s ' + __version__)
parser.add_argument('--extra-delimiter',
                    help='delimiter for different values within one cell')
args = parser.parse_args()

# set verbosity
if args.verbose:
    logs.setLevel('INFO')

# set delimiter
if args.extra_delimiter:
    if len(args.extra_delimiter) == 1:
        subdlm = args.extra_delimiter
    else:
        logging.error('Delimiter has to be a single character')
        exit()

else:
    subdlm = None

# Global variable to hold the active authority configuration
# Will be populated by load_authority_config_from_ini in main()
AUTHORITY_CONFIG = []
GND_PREFIX_URL = 'http://d-nb.info/gnd/' # Default, can be overridden by INI

SUPPORTED_AUTHORITIES = ['gnd', 'viaf', 'loc']

def load_authority_config_from_ini(config_parser, default_config_list):
    """
    Loads authority configuration from the INI file.
    If [AuthorityDetails] is missing or an authority is incompletely configured,
    it falls back to the default_config_list for that authority or in whole.
    """
    new_config = []
    default_config_map = {conf['id']: conf for conf in default_config_list}

    if not config_parser.has_section('AuthorityDetails'):
        logging.warning("No [AuthorityDetails] section in csv2cmi.ini. Using default authority configurations.")
        return default_config_list

    for auth_id in SUPPORTED_AUTHORITIES:
        try:
            pattern = config_parser.get('AuthorityDetails', f'{auth_id}_url_pattern', fallback=None)
            rdf_suffix = config_parser.get('AuthorityDetails', f'{auth_id}_rdf_url_suffix', fallback=None)
            org_query = config_parser.get('AuthorityDetails', f'{auth_id}_org_query', fallback=None)
            person_query = config_parser.get('AuthorityDetails', f'{auth_id}_person_query', fallback=None)

            if not all([pattern, rdf_suffix, org_query, person_query]):
                logging.warning(f"Incomplete configuration for authority '{auth_id}' in csv2cmi.ini. Using default for this authority.")
                if auth_id in default_config_map:
                    new_config.append(default_config_map[auth_id])
                else:
                    logging.error(f"Default configuration missing for critical authority '{auth_id}'. Skipping.")
                continue

            current_auth_config = {
                'id': auth_id,
                'url_pattern': pattern,
                'rdf_url_suffix': rdf_suffix,
                'type_queries': {
                    'organization': org_query,
                    'person': person_query
                },
                'namespaces': dict(RDF_DEFAULT_NAMESPACE), # Start with default RDF
                'error_message_fetch': config_parser.get('AuthorityDetails', f'{auth_id}_error_fetch',
                                                         fallback=default_config_map.get(auth_id, {}).get('error_message_fetch', f"Failed to reach {auth_id.upper()}")),
                'error_message_parse': config_parser.get('AuthorityDetails', f'{auth_id}_error_parse',
                                                         fallback=default_config_map.get(auth_id, {}).get('error_message_parse', f"Unprocessable {auth_id.upper()} file")),
            }

            # GND specific
            if auth_id == 'gnd':
                current_auth_config['person_undifferentiated_type_query'] = config_parser.get('AuthorityDetails', 'gnd_undifferentiated_query', fallback=None)
                current_auth_config['warning_undifferentiated'] = config_parser.get('AuthorityDetails', 'gnd_warning_undifferentiated', 
                                                                                    fallback=default_config_map.get('gnd',{}).get('warning_undifferentiated','Links to undifferentiated Person (GND)'))
                gnd_ns_gndo = config_parser.get('AuthorityDetails', 'gnd_namespace_gndo', fallback=None)
                if gnd_ns_gndo:
                    current_auth_config['namespaces']['gndo'] = gnd_ns_gndo
                elif 'gndo' in default_config_map.get('gnd',{}).get('namespaces',{}): # Check default if not in ini
                    current_auth_config['namespaces']['gndo'] = default_config_map['gnd']['namespaces']['gndo']


            # LOC specific
            if auth_id == 'loc':
                loc_ns_bf = config_parser.get('AuthorityDetails', 'loc_namespace_bf', fallback=None)
                if loc_ns_bf:
                    current_auth_config['namespaces']['bf'] = loc_ns_bf
                elif 'bf' in default_config_map.get('loc',{}).get('namespaces',{}): # Check default if not in ini
                     current_auth_config['namespaces']['bf'] = default_config_map['loc']['namespaces']['bf']


            # If any special query was mandatory and not found, it could be a reason to fallback for this auth.
            # Example: if gnd_undifferentiated_query is critical for GND
            if auth_id == 'gnd' and not current_auth_config['person_undifferentiated_type_query']:
                 if default_config_map.get('gnd',{}).get('person_undifferentiated_type_query'): # check if default has it
                    current_auth_config['person_undifferentiated_type_query'] = default_config_map['gnd']['person_undifferentiated_type_query']
                 else:
                    logging.warning(f"GND undifferentiated query missing for '{auth_id}' in both INI and defaults. GND processing might be affected.")


            new_config.append(current_auth_config)

        except Exception as e:
            logging.error(f"Error processing configuration for authority '{auth_id}' from csv2cmi.ini: {e}. Using default for this authority.")
            if auth_id in default_config_map:
                new_config.append(default_config_map[auth_id])
            else:
                logging.error(f"Default configuration missing for critical authority '{auth_id}' during exception. Skipping.")
    
    if not new_config: # If all authorities failed to load from INI and no defaults were added (e.g. errors)
        logging.warning("Failed to load any authority configurations from INI. Reverting to all defaults.")
        return default_config_list
        
    return new_config


def _parse_correspondent_string(letter_dict, namestring, subdlm_char):
    """
    Parses correspondent strings from the letter dictionary.

    Args:
        letter_dict (dict): The dictionary representing a row in the CSV.
        namestring (str): The key for the correspondent field (e.g., 'sender', 'addressee').
        subdlm_char (str or None): The sub-delimiter character.

    Returns:
        tuple: A tuple containing two lists: persons (list of name strings) and
               personIDs (list of ID strings).
    """
    if not letter_dict.get(namestring):
        return [], []

    persons_str = letter_dict[namestring]
    person_ids_str = letter_dict.get(namestring + "ID", "")

    if subdlm_char:
        persons = [p.strip() for p in persons_str.split(subdlm_char)]
        personIDs = [pid.strip() for pid in person_ids_str.split(subdlm_char)]
    else:
        persons = [persons_str.strip()]
        personIDs = [person_ids_str.strip()]

    # Pad personIDs with empty strings if it's shorter than persons
    if len(personIDs) < len(persons):
        personIDs.extend([''] * (len(persons) - len(personIDs)))

    return persons, personIDs


def _determine_correspondent_type_and_id(person_id_str, namestring, table_line_num, connection, profileDesc, rdf_namespaces):
    """
    Determines the correspondent type (persName or orgName) and processes the authority ID.

    Args:
        person_id_str (str): The authority ID string.
        namestring (str): The key for the correspondent field (e.g., 'sender', 'addressee').
        table_line_num (int): The line number in the CSV file.
        connection (bool): Boolean indicating internet connectivity.
        profileDesc (xml.etree.ElementTree.Element): The profileDesc XML element.

    Returns:
        tuple: A tuple containing (element_tag_name, processed_auth_id).
               element_tag_name is 'persName' or 'orgName'.
               processed_auth_id is the validated authID or an empty string on failure.
    """
    original_person_id_str = person_id_str.strip() # Keep a copy for messages

    if not original_person_id_str:
        return 'persName', ''

    current_person_id = original_person_id_str
    # Use the global GND_PREFIX_URL for prefixing
    if not current_person_id.startswith('http://') and not current_person_id.startswith('https://'):
        logging.debug('Assuming ID %s is a local ID, prepending GND base URL: %s', current_person_id, GND_PREFIX_URL)
        current_person_id = GND_PREFIX_URL + current_person_id
    
    if not connection:
        logging.warning("No internet connection. Cannot verify authority ID %s for %s in line %s. Assuming persName.", 
                        current_person_id, namestring, table_line_num)
        # No caching if no connection, as lookup is not performed.
        return 'persName', current_person_id

    # Check cache after connection check and ID normalization
    if current_person_id in AUTHORITY_CACHE:
        logging.debug(f"Cache hit for ID: {current_person_id} in line {table_line_num}")
        return AUTHORITY_CACHE[current_person_id]
    
    logging.debug(f"Cache miss for ID: {current_person_id} in line {table_line_num}. Performing lookup.")

    # profileDesc.find logic is omitted here as per instructions for simplification for now.

    for authority_conf in AUTHORITY_CONFIG:
        if authority_conf['url_pattern'] in current_person_id:
            rdf_url = current_person_id + authority_conf['rdf_url_suffix']
            try:
                with urllib.request.urlopen(rdf_url) as response:
                    rdf_data = response.read()
                    rdf_root = ElementTree.fromstring(rdf_data.decode('utf-8'))

                    # Handle GND specific UndifferentiatedPerson check first
                    if authority_conf['id'] == 'gnd' and authority_conf.get('person_undifferentiated_type_query'):
                        if rdf_root.find(authority_conf['person_undifferentiated_type_query'], authority_conf['namespaces']):
                            logging.warning(authority_conf['warning_undifferentiated'],
                                            namestring, current_person_id, table_line_num)
                            AUTHORITY_CACHE[current_person_id] = ('persName', '')
                            return 'persName', ''

                    # Check for organization type
                    if rdf_root.find(authority_conf['type_queries']['organization'], authority_conf['namespaces']):
                        AUTHORITY_CACHE[current_person_id] = ('orgName', current_person_id)
                        return 'orgName', current_person_id
                    
                    # Check for person type
                    if rdf_root.find(authority_conf['type_queries']['person'], authority_conf['namespaces']):
                        AUTHORITY_CACHE[current_person_id] = ('persName', current_person_id)
                        return 'persName', current_person_id

                    # If no type determined after checking queries
                    logging.warning(authority_conf['error_message_parse'],
                                    namestring, current_person_id, table_line_num)
                    AUTHORITY_CACHE[current_person_id] = ('persName', '')
                    return 'persName', ''

            except urllib.error.HTTPError as e:
                logging.error(authority_conf['error_message_fetch'] + ' (HTTP %s: %s)',
                              namestring, current_person_id, table_line_num, e.code, e.reason)
                AUTHORITY_CACHE[current_person_id] = ('persName', '') # Cache failure
                return 'persName', ''
            except urllib.error.URLError as e:
                logging.error(authority_conf['error_message_fetch'] + ' (URL Error: %s)',
                              namestring, current_person_id, table_line_num, e.reason)
                AUTHORITY_CACHE[current_person_id] = ('persName', '') # Cache failure
                return 'persName', ''
            except ElementTree.ParseError as e:
                logging.error(authority_conf.get('error_message_parse', 'Failed to parse XML for %sID %s in line %s (authority: %s)') + ': %s',
                              namestring, current_person_id, table_line_num, authority_conf['id'], e)
                AUTHORITY_CACHE[current_person_id] = ('persName', '') # Cache failure
                return 'persName', ''
            except Exception as e: 
                logging.error('An unexpected error occurred while processing %sID %s in line %s for authority %s: %s',
                              namestring, current_person_id, table_line_num, authority_conf['id'], e)
                AUTHORITY_CACHE[current_person_id] = ('persName', '') # Cache failure
                return 'persName', ''
            
            break 
    else: 
        if 'http://' in current_person_id or 'https://' in current_person_id:
            logging.error('No proper authority record provider identified for %sID %s in line %s. Assuming persName.',
                          namestring, current_person_id, table_line_num)
            AUTHORITY_CACHE[current_person_id] = ('persName', '') # Cache this outcome
            return 'persName', '' 
    
    # Fallback: if loop completed without break and person_id was not a URL (so no error logged above)
    # or some other unhandled case. This should ideally not be reached if current_person_id
    # was a URL that didn't match any pattern (handled by for/else) or if it was processed.
    # Caching this default outcome too.
    logging.debug(f"ID {current_person_id} did not match any authority provider or failed processing. Defaulting and caching.")
    AUTHORITY_CACHE[current_person_id] = ('persName', '')
    return 'persName', ''


def _create_xml_element_for_correspondent(person_name_str, element_tag_name, auth_id_str, table_line_num):
    """
    Creates an XML element for a single correspondent.

    Args:
        person_name_str (str): The name of the correspondent.
        element_tag_name (str): The tag name for the element ('persName' or 'orgName').
        auth_id_str (str): The authority ID, if available.
        table_line_num (int): The line number in the CSV file (for logging).

    Returns:
        xml.etree.ElementTree.Element: The created XML element.
    """
    correspondent_element = Element(element_tag_name)

    if auth_id_str:
        correspondent_element.set('ref', auth_id_str)

    person_name_processed = person_name_str.strip()
    if person_name_processed.startswith('[') and person_name_processed.endswith(']'):
        correspondent_element.set('evidence', 'conjecture')
        person_name_processed = person_name_processed[1:-1]
        logging.info('Added @evidence to <%s> from line %s', element_tag_name, table_line_num)

    correspondent_element.text = person_name_processed
    return correspondent_element


def checkIsodate(datestring):
    try:
        datetime.strptime(datestring, '%Y-%m-%d')
        return True
    except ValueError:
        try:
            datetime.strptime(datestring, '%Y-%m')
            return True
        except ValueError:
            try:
                datetime.strptime(datestring, '%Y')
                return True
            except ValueError:
                return False


def checkDatableW3C(datestring):
    if checkIsodate(datestring):
        return True
    else:
        try:
            datetime.strptime(datestring, '--%m-%d')
            return True
        except ValueError:
            try:
                datetime.strptime(datestring, '--%m')
                return True
            except ValueError:
                try:
                    datetime.strptime(datestring, '---%d')
                    return True
                except ValueError:
                    return False


def checkConnectivity():
    try:
        urllib.request.urlopen('http://193.175.100.220', timeout=1)
        return True
    except urllib.error.URLError:
        logging.error('No internet connection')
        return False


def createTextstructure():
    # creates an empty TEI text body
    text = Element('text')
    body = SubElement(text, 'body')
    SubElement(body, 'p')
    return text


def createFileDesc(config):
    # creates a file description from config file
    fileDesc = Element('fileDesc')
    # title statement
    titleStmt = SubElement(fileDesc, 'titleStmt')
    title = SubElement(titleStmt, 'title')
    title.set('xml:id', createID('title'))
    title.text = config.get(
        'Project', 'title', fallback='untitled letters project')
    editor = SubElement(titleStmt, 'editor')
    editor.text = config.get('Project', 'editor')
    # publication statement
    publicationStmt = SubElement(fileDesc, 'publicationStmt')
    publisher = SubElement(publicationStmt, 'publisher')
    if (config.get('Project', 'publisher')):
        publisher.text = config.get('Project', 'publisher')
    else:
        publisher.text = config.get('Project', 'editor')
    idno = SubElement(publicationStmt, 'idno')
    idno.set('type', 'url')
    idno.text = config.get('Project', 'fileURL')
    date = SubElement(publicationStmt, 'date')
    date.set('when', str(datetime.now().isoformat()))
    availability = SubElement(publicationStmt, 'availability')
    licence = SubElement(availability, 'licence')
    licence.set('target', 'https://creativecommons.org/licenses/by/4.0/')
    licence.text = 'This file is licensed under the terms of the Creative-Commons-License CC-BY 4.0'
    return fileDesc


def createCorrespondent(namestring):
    """
    Creates a list of XML elements for correspondents (sender or addressee).
    """
    # Global variables used: letter, subdlm, table, connection, profileDesc
    # These are assumed to be available in the scope, as per the original design.

    persons, personIDs = _parse_correspondent_string(
        letter, namestring, subdlm)

    if not persons:
        return []

    correspondent_elements = []
    for index, person_name in enumerate(persons):
        person_id = personIDs[index] if index < len(personIDs) else ""

            # Pass RDF_DEFAULT_NAMESPACE to the function
        element_tag, processed_id = _determine_correspondent_type_and_id(
            person_id,
            namestring,
            table.line_num,
            connection,
                profileDesc, # profileDesc is still passed but not used for pre-check in the refactored version
                RDF_DEFAULT_NAMESPACE
        )

        xml_element = _create_xml_element_for_correspondent(
            person_name,
            element_tag,
            processed_id,
            table.line_num
        )
        correspondent_elements.append(xml_element)

    return correspondent_elements


def createDate(dateString):
    date = Element('date')
    # normalize date
    normalizedDate = dateString.translate(dateString.maketrans('', '', '?~%'))
    if checkDatableW3C(normalizedDate):
        date.set('when', str(normalizedDate))
    elif normalizedDate.startswith('[') and normalizedDate.endswith(']'):
        # one of set
        dateList = normalizedDate[1:-1].split(",")
        dateFirst = dateList[0].split(".")[0]
        dateLast = dateList[-1].split(".")[-1]
        if dateFirst or dateLast:
            if checkDatableW3C(dateFirst):
                date.set('notBefore', str(dateFirst))
            if checkDatableW3C(dateLast):
                date.set('notAfter', str(dateLast))
    else:
        # time interval
        dateList = normalizedDate.split('/')
        if len(dateList) == 2 and (dateList[0] or dateList[1]):
            if checkDatableW3C(dateList[0]):
                date.set('from', str(dateList[0]))
            if checkDatableW3C(dateList[1]):
                date.set('to', str(dateList[1]))
    if date.attrib:
        if normalizedDate != dateString:
            date.set('cert', 'medium')
            logging.info(
                'Added @cert to <date> from line %s', table.line_num)
        return date
    else:
        return None


def createPlaceName(placestring):
    # creates a placeName element
    placeName = Element('placeName')
    letter[placestring] = letter[placestring].strip()
    if letter[placestring].startswith('[') and letter[placestring].endswith(']'):
        placeName.set('evidence', 'conjecture')
        letter[placestring] = letter[placestring][1:-1]
        logging.info('Added @evidence to <placeName> from line %s',
                     table.line_num)
    placeName.text = str(letter[placestring])
    if (placestring + 'ID' in table.fieldnames) and (letter[placestring + 'ID']):
        letter[placestring + 'ID'] = letter[placestring + 'ID'].strip()
        if 'http://www.geonames.org/' in letter[placestring + 'ID']:
            placeName.set('ref', str(letter[placestring + 'ID']))
        else:
            logging.warning('No standardized %sID in line %s',
                            placestring, table.line_num)
    else:
        logging.debug('ID for "%s" missing in line %s', letter[
            placestring], table.line_num)
    return placeName


def createEdition(editionTitle, biblID):
    # creates a new bibliographic entry
    editionType = 'print'
    if ('Edition' in config) and ('type' in config['Edition']):
        if config.get('Edition', 'type') in ['print', 'hybrid', 'online']:
            editionType = config.get('Edition', 'type')
    bibl = Element('bibl')
    bibl.text = editionTitle
    bibl.set('type', editionType)
    bibl.set('xml:id', biblID)
    return bibl


def getEditonID(editionTitle):
    editionID = ''
    for bibl in sourceDesc.findall('bibl'):
        if editionTitle == bibl.text:
            editionID = bibl.get('xml:id')
            break
    return editionID


def createID(id_prefix):
    if (id_prefix.strip() == ''):
        id_prefix = ''.join(random.choice(
            string.ascii_lowercase + string.digits) for _ in range(8))
    fullID = id_prefix.strip() + '_' + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(
        8)) + '_' + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    return fullID

def main():

    # simple test for file
    try:
        open(args.filename, 'rt').close()
    except FileNotFoundError:
        logging.error('File not found')
        exit()

    # check internet connection via DNB
    connection = checkConnectivity()

    # read config file
    global config, AUTHORITY_CONFIG, GND_PREFIX_URL
    config_parser = configparser.ConfigParser()
    # set default values for Project section, others might come from ini or defaults
    config_parser['Project'] = {'editor': '', 'publisher': '', 'fileURL': os.path.splitext(
        os.path.basename(args.filename))[0] + '.xml'}
    
    ini_path = 'csv2cmi.ini'
    try:
        with open(ini_path, 'rt') as f:
            config_parser.read_file(f)
        logging.info(f"Successfully read configuration from {ini_path}")
    except IOError:
        logging.warning(f"{ini_path} not found. Using default settings for project and authority configurations.")
        # Keep config_parser as it is (with only Project defaults)

    # Update global config to be this instance
    config = config_parser

    # Load authority configurations
    AUTHORITY_CONFIG = load_authority_config_from_ini(config, DEFAULT_AUTHORITY_CONFIG)
    
    # Update GND_PREFIX_URL from INI if available
    GND_PREFIX_URL = config.get('AuthorityDetails', 'gnd_default_prefix', fallback=GND_PREFIX_URL)
    if GND_PREFIX_URL != 'http://d-nb.info/gnd/' : # Log if it changed from compile-time default
        logging.info(f"GND prefix URL set to: {GND_PREFIX_URL} from INI file.")


    # building cmi
    # generating root element
    root = Element('TEI')
    root.set('xmlns', 'http://www.tei-c.org/ns/1.0')
    root.append(
        Comment(' Generated from table of letters with csv2cmi ' + __version__ + ' '))

    # teiHeader
    teiHeader = SubElement(root, 'teiHeader')
    # create a file description from config file
    fileDesc = createFileDesc(config)
    teiHeader.append(fileDesc)
    # container for bibliographic data
    global sourceDesc
    sourceDesc = SubElement(fileDesc, 'sourceDesc')
    # filling in correspondance meta-data
    profileDesc = SubElement(teiHeader, 'profileDesc')

    with open(args.filename, 'rt') as letterTable:
        global table
        table = DictReader(letterTable)
        logging.debug('Recognized columns: %s', table.fieldnames)
        if not ('sender' in table.fieldnames and 'addressee' in table.fieldnames):
            logging.error('No sender/addressee field in table')
            exit()
        edition = ''
        if not('edition' in table.fieldnames):
            try:
                edition = config.get('Edition', 'title')
            except configparser.Error:
                logging.warning('No edition stated. Please set manually.')
            sourceDesc.append(createEdition(edition, createID('edition')))
        global letter
        for letter in table:
            if ('edition' in table.fieldnames):
                edition = letter['edition'].strip()
                editionID = getEditonID(edition)
                if not(edition or args.all):
                    continue
                if edition and not editionID:
                    editionID = createID('edition')
                    sourceDesc.append(createEdition(edition, editionID))
            entry = Element('correspDesc')
            if args.line_numbers:
                entry.set('n', str(table.line_num))
            entry.set('xml:id', createID('letter'))
            if edition:
                entry.set('source', '#' + editionID)
            if 'key' in table.fieldnames and letter['key']:
                if not(edition):
                    logging.error(
                        'Key without edition in line %s', table.line_num)
                else:
                    if 'http://' in str(letter['key']):
                        entry.set('ref', str(letter['key']).strip())
                    else:
                        entry.set('key', str(letter['key']).strip())

            # sender info block
            if letter['sender'] or ('senderPlace' in table.fieldnames and letter['senderPlace']) or letter['senderDate']:
                action = SubElement(entry, 'correspAction')
                action.set('xml:id', createID('sender'))
                action.set('type', 'sent')

                # add persName or orgName
                if letter['sender']:
                    correspondents = createCorrespondent('sender')
                    for sender in correspondents:
                        action.append(sender)
                # add placeName
                if ('senderPlace' in table.fieldnames) and letter['senderPlace']:
                    action.append(createPlaceName('senderPlace'))
                # add date
                if 'senderDate' in table.fieldnames and letter['senderDate']:
                    try:
                        action.append(createDate(letter['senderDate']))
                    except TypeError:
                        logging.warning(
                            'Could not parse senderDate in line %s', table.line_num)
            else:
                logging.info(
                    'No information on sender in line %s', table.line_num)

            # addressee info block
            if letter['addressee'] or ('addresseePlace' in table.fieldnames and letter['addresseePlace']) or ('addresseeDate' in table.fieldnames and letter['addresseeDate']):
                action = SubElement(entry, 'correspAction')
                action.set('xml:id', createID('addressee'))
                action.set('type', 'received')

                # add persName or orgName
                if letter['addressee']:
                    correspondents = createCorrespondent('addressee')
                    for addressee in correspondents:
                        action.append(addressee)
                # add placeName
                if ('addresseePlace' in table.fieldnames) and letter['addresseePlace']:
                    action.append(createPlaceName('addresseePlace'))
                # add date
                if 'addresseeDate' in table.fieldnames and letter['addresseeDate']:
                    try:
                        action.append(createDate(letter['addresseeDate']))
                    except TypeError:
                        logging.warning(
                            'Could not parse addresseeDate in line %s', table.line_num)
            else:
                logging.info('No information on addressee in line %s',
                             table.line_num)
            if args.notes:
                if ('note' in table.fieldnames) and letter['note']:
                    note = SubElement(entry, 'note')
                    note.set('xml:id', createID('note'))
                    note.text = str(letter['note'])
            if entry.find('*'):
                profileDesc.append(entry)

        # generate empty body
    root.append(createTextstructure())

    # save cmi to file
    tree = ElementTree(root)
    tree.write(os.path.splitext(os.path.basename(args.filename))[
               0] + '.xml', encoding="utf-8", xml_declaration=True, method="xml")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.warning('Rolling back …')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
