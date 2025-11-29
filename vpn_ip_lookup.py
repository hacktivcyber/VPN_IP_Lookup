import argparse
import requests
import csv
import sys
import geocoder


# --- Utility Functions ---

def flatten_json(y):
    """
    Flattens a nested JSON object into a single-level dictionary.
    """
    out = {}

    def flatten(x, name=''):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + '_')
        elif type(x) is list:
            i = 0
            for a in x:
                flatten(a, name + str(i) + '_')
                i += 1
        else:
            out[name[:-1]] = x

    flatten(y)
    return out


def perform_lookup(ip_address, api_key):
    """
    Performs an API lookup for a given IP address.

    Args:
        ip_address (str): The IP address to look up.
        api_key (str): The API key for vpnapi.io.

    Returns:
        dict: The JSON response from the API as a dictionary, or None on error.
    """
    url = f"https://vpnapi.io/api/{ip_address}?key={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raises an exception for 4XX/5XX errors
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error looking up {ip_address}: {e}", file=sys.stderr)
        return None


# New function for reverse geocoding
def reverse_geocode_lookup(latitude, longitude, opencage_api_key):
    """
    Performs a reverse geocode lookup using OpenCage's Geocoding API.

    Args:
        latitude (str): The latitude coordinate.
        longitude (str): The longitude coordinate.
        opencage_api_key (str): The API key for OpenCage Geocoding API.

    Returns:
        dict: A dictionary with 'opencage_country', 'opencage_state', and 'opencage_city',
              or default empty strings on failure.
    """
    try:
        # Geocoder expects latitude and longitude as floats
        lat = float(latitude)
        lng = float(longitude)
    except ValueError:
        print(f"Warning: Invalid latitude/longitude: {latitude}, {longitude}", file=sys.stderr)
        return {
            "opencage_country": "",
            "opencage_state": "",
            "opencage_city": "",
        }

    try:
        # Use the OpenCage provider for reverse geocoding
        g = geocoder.opencage([lat, lng], key=opencage_api_key, method='reverse')

        if g.ok:
            return {
                # Note: OpenCase Reverse Geocoder provides both short and long names for country/state.
                # 'country_code' is the short name (e.g., 'US'), 'country' is the full name.
                # 'state_code' is the short name (e.g CA), 'state' is the full name.
                # Using 'opencage' for clarity in the output.
                "opencage_country": g.country if g.country else "",
                "opencage_state": g.state if g.state else "",  # State/Province full name
                "opencage_city": g.city if g.city else "",
            }
        else:
            print(f"Warning: OpenCage Geocoding failed for {lat}, {lng}. Status: {g.status}", file=sys.stderr)
            return {
                "opencage_country": "",
                "opencage_state": "",
                "opencage_city": "",
            }
    except Exception as e:
        print(f"Error during OpenCage Geocoding lookup: {e}", file=sys.stderr)
        return {
            "opencage_country": "",
            "opencage_state": "",
            "opencage_city": "",
        }


# --- Main Application Logic ---

def main():
    """
    Main function to parse arguments, read IPs, perform lookups, and write to CSV.
    """
    parser = argparse.ArgumentParser(
        description="Perform IP address lookups using the vpnapi.io service and enrich data with OpenCage reverse geocoding.")
    parser.add_argument("-i", "--input-file", required=True,
                        help="Path to the text file containing a list of IP addresses.")
    parser.add_argument("-a", "--api-key", required=True, help="Your API key for vpnapi.io (IP lookup).")
    parser.add_argument("-c", "--opencage-key", required=True,
                        help="Your API key for OpenCage Geocoding API (Reverse Geolocation).")  # New argument
    parser.add_argument("-w", "--write-file", required=True,
                        help="Path to the output CSV file where results will be written.")

    args = parser.parse_args()

    input_file = args.input_file
    vpn_api_key = args.api_key
    opencage_api_key = args.opencage_key
    output_file = args.write_file

    # Define the new fields we are adding to the CSV header
    new_geo_fields = ["opencage_country", "opencage_state", "opencage_city"]
    header_written = False

    print(f"Reading IP addresses from: {input_file}")
    print(f"CSV output will be written to: {output_file}")

    try:
        # Read all IPs from the input file into a list
        with open(input_file, 'r') as infile:
            ips = [line.strip() for line in infile if line.strip()]

        # Deduplicate using a set and then sort the list
        unique_sorted_ips = sorted(list(set(ips)))

        print(f"Found {len(ips)} total IP(s). Processing {len(unique_sorted_ips)} unique IP(s).")

        with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
            writer = None
            total_to_process = len(unique_sorted_ips)

            # Iterate over the unique, sorted list of IPs
            for i, ip in enumerate(unique_sorted_ips):
                remaining = total_to_process - (i + 1)
                print(f"Looking up: {ip}... ({remaining} IPs remaining)")

                # Perform the primary VPN API lookup
                data = perform_lookup(ip, vpn_api_key)

                if data:
                    # Flatten the nested JSON data
                    flat_data = flatten_json(data)

                    # Initialize geo data with empty strings
                    geo_data = {
                        "opencage_country": "",
                        "opencage_state": "",
                        "opencage_city": "",
                    }

                    # Perform reverse geocoding if latitude and longitude data exist
                    # The vpnapi.io data always provides latitude and longitude (even if empty city/region)
                    # The keys will be: location_latitude and location_longitude
                    latitude = flat_data.get("location_latitude")
                    longitude = flat_data.get("location_longitude")

                    if latitude and longitude:
                        geo_data = reverse_geocode_lookup(latitude, longitude, opencage_api_key)

                    # Merge the geo data into the flat IP data
                    flat_data.update(geo_data)

                    # On the first successful lookup, determine and write the header row
                    if not header_written:
                        # Ensure the new geo fields are included at the end of the header
                        # The order is important for a nice-looking CSV
                        original_header = list(flat_data.keys())

                        # Remove the new fields from the temporary header if they somehow ended up there
                        for field in new_geo_fields:
                            if field in original_header:
                                original_header.remove(field)

                        final_header = original_header + new_geo_fields

                        writer = csv.DictWriter(outfile, fieldnames=final_header)
                        writer.writeheader()
                        header_written = True

                    # Write the data row to the CSV
                    if writer:
                        writer.writerow(flat_data)

    except FileNotFoundError:
        print(f"Error: Input file not found at '{input_file}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    print("\nLookup process finished.")
    if not header_written:
        print("Warning: No successful lookups were performed, so the output file is empty.")

if __name__ == "__main__":
    main()
