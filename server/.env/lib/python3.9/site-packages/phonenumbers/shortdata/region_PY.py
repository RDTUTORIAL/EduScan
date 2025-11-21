"""Auto-generated file, do not edit by hand. PY metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_PY = PhoneMetadata(id='PY', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[159]\\d\\d(?:\\d{4})?', possible_length=(3, 7)),
    toll_free=PhoneNumberDesc(national_number_pattern='128|911', example_number='128', possible_length=(3,)),
    emergency=PhoneNumberDesc(national_number_pattern='128|911', example_number='128', possible_length=(3,)),
    short_code=PhoneNumberDesc(national_number_pattern='(?:1[01]|51)\\d{5}|911|1[1-9]\\d', example_number='110', possible_length=(3, 7)),
    carrier_specific=PhoneNumberDesc(national_number_pattern='(?:1[01]|51)\\d{5}', example_number='1000000', possible_length=(7,)),
    sms_services=PhoneNumberDesc(national_number_pattern='(?:1[01]|51)\\d{5}', example_number='1000000', possible_length=(7,)),
    short_data=True)
