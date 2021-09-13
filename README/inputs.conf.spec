[axonius_saved_query://<name>]
api_host = The URL of the Axonius web host
api_key = The API Key from https://axonius.example.com/account -> API Key
api_secret = The API Secret from https://axonius.example.com/account -> API Key
entity_type = The entity type of the saved query, either devices or users
saved_query = The name of the saved query
page_size = The number of asset entities to fetch during each API call, higher is quicker while lower takes less memory
standoff_ms = The number of milliseconds to wait between successive API calls
dynamic_field_mapping = Rename fields using a JSON-formatted string, renaming occurs prior to data ingest
shorten_field_names = Truncate the field name prefix, if applicable (specific_data.data, adapters_data)
incremental_data_ingest = Include only the entities that have a fetch timer newer than last collection
enforce_ssl_validation = Enforce SSL certificate validation (the Splunk server's global certificate trust will be used if CA Bundle Path is left blank)
ssl_certificate_path = The filesystem path to the CA bundle used for SSL certificate validation