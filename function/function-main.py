import requests
import json


def hello_world(request):
    """Responds to any HTTP request.
    Args:
        request (flask.Request): HTTP request object.
    Returns:
        The response text or any set of values that can be turned into a
        Response object using
        `make_response <http://flask.pocoo.org/docs/1.0/api/#flask.Flask.make_response>`.
    """
    request_json = request.get_json()
    if (request.args and "ipaddress" in request.args) or (
        request_json and "ipaddress" in request_json
    ):
        ip_address = None
        if request.args and "ipaddress" in request.args:
            ip_address = request.args.get("ipaddress")
        else:
            ip_address = request_json["ipaddress"]

        result = {}

        def get_location(ip_address):
            response = requests.get(f"https://ipapi.co/{ip_address}/json/").json()
            location_data = {
                "ip": ip_address,
                "city": response.get("city"),
                "region": response.get("region"),
                "country": response.get("country_name"),
            }
            return location_data

        def get_virus_total_info(ip_address):
            virus_key = (
                "7feefb77684feb0a5a84c0e0509ec3730026278380a640da82e2f160b07beff4"
            )
            virus_url = "https://www.virustotal.com/api/v3/ip_addresses/{}".format(
                ip_address
            )
            headers = {"x-apikey": virus_key}
            response = requests.get(url=virus_url, headers=headers)
            return response.json()

        def get_whois_info(ip_address):
            whois_url = "https://whoisjson.com/api/v1/reverseWhois"
            whois_api_key = (
                "c324b70a62d004984d35fcde90933077f68e0b89b4b35f7a552419c19ab03855"
            )
            whois_headers = {"Authorization": "TOKEN={}".format(whois_api_key)}
            whois_data = {"ip": ip_address}
            response = requests.get(
                url=whois_url, headers=whois_headers, params=whois_data
            )
            return response.json()

        result["geolocation"] = get_location(ip_address)
        result["virus_total"] = get_virus_total_info(ip_address)
        result["Whois_info"] = get_whois_info(ip_address)

        return json.dumps(result), 200, {"Content-Type": "application/json"}
    else:
        return "You need to provide ipaddress!", 400
