import argparse
import requests
import csv
import sys
import geocoder
import ipaddress

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

def is_ip_in_cached_networks(ip_str, cidr_cache):
    """
    Checks if the given IP address belongs to a CIDR range already in the cache.

    Returns:
        str: The CIDR string if found, otherwise None.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        # cidr_cache keys are the CIDR strings
        for cidr in cidr_cache.keys():
            if ip_obj in ipaddress.ip_network(cidr):
                return cidr
    except ValueError:
        # Handles cases where ip_str or cidr might be invalid
        pass
    return None


def perform_lookup(ip_address, api_key):
    """
    Performs an API lookup for a given IP address.
    
    Returns:
        JSON: VPNAPI lookup Results if found, otherwise None.
    """
    url = f"https://vpnapi.io/api/{ip_address}?key={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error looking up {ip_address}: {e}", file=sys.stderr)
        return None


def reverse_geocode_lookup(latitude, longitude, opencage_api_key):
    """
    Performs a reverse geocode lookup using OpenCage's Geocoding API.
    
    Returns:
        str:  Country, Stats & City values for Latitude & Longitude lookup at OpenCage if found, otherwise blank strings for Country, Stats & City.
    """
    default_geo_data = {
        "opencage_country": "",
        "opencage_state": "",
        "opencage_city": "",
    }

    try:
        lat = float(latitude)
        lng = float(longitude)
    except (ValueError, TypeError):
        return default_geo_data

    try:
        g = geocoder.opencage([lat, lng], key=opencage_api_key, method='reverse')
        if g.ok:
            return {
                "opencage_country": g.country if g.country else "",
                "opencage_state": g.state if g.state else "",
                "opencage_city": g.city if g.city else "",
            }
        return default_geo_data
    except Exception:
        return default_geo_data

# --- Main Application Logic ---
def main():
    parser = argparse.ArgumentParser(
        description="vpnapi.io IP lookup with CIDR and Geolocation caching.")
    parser.add_argument("-i", "--input-file", required=True)
    parser.add_argument("-a", "--api-key", required=True)
    parser.add_argument("-c", "--opencage-key", required=True)
    parser.add_argument("-w", "--write-file", required=True)

    args = parser.parse_args()

    # Caches
    # CIDR -> Full JSON response data. The key is the CIDR string (e.g., "192.0.2.0/24")
    cidr_cache = {}
    reverse_geocode_cache = {}  # (lat, lon) -> Geocode dict

    new_geo_fields = ["opencage_country", "opencage_state", "opencage_city"]
    header_written = False

    try:
        with open(args.input_file, 'r') as infile:
            ips = [line.strip() for line in infile if line.strip()]

        unique_sorted_ips = sorted(list(set(ips)))
        total_to_process = len(unique_sorted_ips)

        with open(args.write_file, 'w', newline='', encoding='utf-8') as outfile:
            writer = None

            for i, ip in enumerate(unique_sorted_ips):
                remaining = total_to_process - (i + 1)
                print(f"\nProcessing IP: {ip} ({remaining} remaining)")

                # --- 1. Check CIDR Cache ---
                matched_cidr = is_ip_in_cached_networks(ip, cidr_cache)

                if matched_cidr:
                    print(f"-> Using cached VPN API results for IP: {ip} (IP belongs to already processed CIDR: {matched_cidr})")
                    data = cidr_cache[matched_cidr]
                else:
                    print(f"-> Performing new VPN API lookup...")
                    data = perform_lookup(ip, args.api_key)

                    # --- CRITICAL FIX: Use the correct nested key for the CIDR ---
                    if data and "network" in data and "network" in data["network"]:
                        # Accessing data['network']['network']
                        current_cidr = data["network"]["network"]
                        cidr_cache[current_cidr] = data
                        print(f"-> Caching CIDR: {current_cidr}")

                if data:
                    flat_data = flatten_json(data)
                    # Ensure the 'ip' field in the CSV reflects the current IP being processed
                    flat_data['ip'] = ip

                    geo_data = {field: "" for field in new_geo_fields}
                    lat = flat_data.get("location_latitude")
                    lng = flat_data.get("location_longitude")

                    # --- 2. Check Geo Cache ---
                    if lat and lng:
                        coord_key = (lat, lng)
                        if coord_key in reverse_geocode_cache:
                            print(f"-> Using cached geocode for coordinates: {lat}, {lng}")
                            geo_data = reverse_geocode_cache[coord_key]
                        else:
                            print(f"-> Performing new geocode lookup for: {lat}, {lng}")
                            geo_data = reverse_geocode_lookup(lat, lng, args.opencage_key)
                            reverse_geocode_cache[coord_key] = geo_data

                    flat_data.update(geo_data)

                    # --- 3. CSV Writing (Only on the first successful lookup) ---
                    if not header_written:
                        original_header = list(flat_data.keys())
                        for field in new_geo_fields:
                            if field in original_header: original_header.remove(field)
                        final_header = original_header + new_geo_fields
                        writer = csv.DictWriter(outfile, fieldnames=final_header)
                        writer.writeheader()
                        header_written = True

                    if writer:
                        writer.writerow(flat_data)

    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    print("\nProcess finished.")

if __name__ == "__main__":
    main()
