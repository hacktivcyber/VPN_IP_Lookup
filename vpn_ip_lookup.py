import argparse
import requests
import csv
import sys
import geocoder
import ipaddress
import os
import logging  # <-- NEW: Import the logging module

# Global variable for the logger (it will be initialized in main)
logger = None


# --- NEW: Logging Setup Function ---
def setup_logging(job_name, output_directory):
    """
    Configures the application-wide logging capability to write to
    both the {jobName}.log file (append mode) and the console (stdout).
    """
    global logger
    log_filepath = os.path.join(output_directory, f"{job_name}.log")

    # Create the logger
    logger = logging.getLogger(job_name)
    logger.setLevel(logging.INFO)  # Set the minimum logging level

    # Define a common formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # --- 1. File Handler (for {jobName}.log) ---
    file_handler = logging.FileHandler(log_filepath, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.INFO)  # Write all INFO and above to file
    file_handler.setFormatter(formatter)

    # --- 2. Console Handler (for stdout/stderr) ---
    # This handler sends messages to the terminal
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)  # Write all INFO and above to console
    console_handler.setFormatter(formatter)

    # Ensure handlers are added only once
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    logger.info(f"Logging initialized. Output file: {log_filepath}")

# --- Utility Functions ---
# (Modified to accept and use the logger)
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
        for cidr in cidr_cache.keys():
            if ip_obj in ipaddress.ip_network(cidr):
                return cidr
    except ValueError:
        pass
    return None


def perform_lookup(ip_address, api_key, logger):  # <-- Added logger
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
        logger.error(f"Error looking up {ip_address}: {e}")  # <-- Used logger.error
        return None


def reverse_geocode_lookup(latitude, longitude, opencage_api_key, logger):  # <-- Added logger
    """
    Performs a reverse geocode lookup using OpenCage's Geocoding API.

    Returns:
        str: Country, Stats & City values for Latitude & Longitude lookup at OpenCage if found, otherwise blank strings for Country, Stats & City.
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
        # logger.warning(f"Invalid latitude/longitude ({latitude}, {longitude}). Skipping geocode.") # Too noisy
        return default_geo_data

    try:
        g = geocoder.opencage([lat, lng], key=opencage_api_key, method='reverse')
        if g.ok:
            return {
                "opencage_country": g.country if g.country else "",
                "opencage_state": g.state if g.state else "",
                "opencage_city": g.city if g.city else "",
            }
        logger.warning(f"OpenCage lookup failed for ({lat}, {lng}). Status: {g.status}")  # <-- Used logger.warning
        return default_geo_data
    except Exception as e:
        logger.error(f"Unexpected error during OpenCage lookup for ({lat}, {lng}): {e}")  # <-- Used logger.error
        return default_geo_data


# --- Persistent Cache Loading Function (from CSV) ---

def load_cache_from_csv(cache_filepath, cidr_key="network_network", lat_key="location_latitude",
                        lon_key="location_longitude"):
    """
    Loads persistent CIDR and Geocode caches from an existing CSV file (which acts as the cache).
    """
    cidr_cache = {}
    reverse_geocode_cache = {}
    processed_ips = set()
    existing_rows = []

    global logger

    if not os.path.exists(cache_filepath):
        logger.info(f"Cache file not found at {cache_filepath}. Starting fresh.")  # <-- Used logger.info
        return cidr_cache, reverse_geocode_cache, processed_ips, []

    logger.info(f"Loading existing cache from {cache_filepath}...")  # <-- Used logger.info

    try:
        with open(cache_filepath, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            # Check for required headers
            header = reader.fieldnames
            required_keys = ['ip', cidr_key, lat_key, lon_key, 'opencage_country', 'opencage_state', 'opencage_city']
            if not all(k in header for k in required_keys):
                logger.warning(
                    f"Cache file {cache_filepath} is missing required headers. Starting fresh.")  # <-- Used logger.warning
                return cidr_cache, reverse_geocode_cache, processed_ips, []

            for row in reader:
                existing_rows.append(row)

                # 1. Populate CIDR Cache
                current_cidr = row.get(cidr_key)
                if current_cidr:
                    cidr_cache[current_cidr] = row.copy()

                # 2. Populate Geocode Cache
                lat_str = row.get(lat_key)
                lng_str = row.get(lon_key)
                if lat_str and lng_str:
                    try:
                        coord_key = (float(lat_str), float(lng_str))

                        geo_data = {
                            "opencage_country": row.get("opencage_country", ""),
                            "opencage_state": row.get("opencage_state", ""),
                            "opencage_city": row.get("opencage_city", ""),
                        }
                        reverse_geocode_cache[coord_key] = geo_data
                    except ValueError:
                        logger.warning(
                            f"Invalid coordinates in cache row for lat/lon: {lat_str}/{lng_str}")  # <-- Used logger.warning

                # 3. Track Processed IPs
                processed_ips.add(row.get('ip'))

        logger.info(f"Loaded {len(cidr_cache)} unique CIDR entries.")  # <-- Used logger.info
        logger.info(f"Loaded {len(reverse_geocode_cache)} unique Geocode entries.")  # <-- Used logger.info
        return cidr_cache, reverse_geocode_cache, processed_ips, existing_rows

    except Exception as e:
        logger.error(
            f"Error loading cache file {cache_filepath}: {e}. Starting with empty cache.")  # <-- Used logger.error
        return cidr_cache, reverse_geocode_cache, processed_ips, []


# --- Main Application Logic ---
def main():
    parser = argparse.ArgumentParser(
        description="vpnapi.io IP lookup with CIDR and Geolocation caching. Output CSV also serves as persistent cache.")
    parser.add_argument("-i", "--input-file", required=True)
    parser.add_argument("-a", "--api-key", required=True)
    parser.add_argument("-c", "--opencage-key", required=True)
    # The new -o argument specifies the directory for all output
    parser.add_argument("-o", "--output-directory", required=True,
                        help="The directory where the output CSV and cache file will be saved.")
    # The -j argument specifies the name for the shared cache/output file
    parser.add_argument("-j", "--jobName", required=True,
                        help="The name for the persistent cache/output file (e.g., 'master_cache').")

    args = parser.parse_args()

    # 1. Setup Logging FIRST
    os.makedirs(args.output_directory, exist_ok=True)
    setup_logging(args.jobName, args.output_directory)

    global logger

    # Construct the full cache/output file path
    output_filepath = os.path.join(args.output_directory, f"{args.jobName}.csv")

    # Load persistent cache and existing rows from the CSV
    # processed_ips and existing_rows are now primarily used to set up the writer header
    # and for the CIDR/Geo caches.
    cidr_cache, reverse_geocode_cache, processed_ips, existing_rows = load_cache_from_csv(output_filepath)

    new_geo_fields = ["opencage_country", "opencage_state", "opencage_city"]
    header_written = bool(existing_rows)

    try:
        with open(args.input_file, 'r') as infile:
            # --- CHANGE 1: DO NOT FILTER PROCESSED IPs ---
            # Read all input IPs, including duplicates and already processed ones.
            ips_from_file = [line.strip() for line in infile if line.strip()]

        # We must track how many times an IP appears in the input file
        # We process them in the order and quantity they appear in the file.
        unique_sorted_ips = [ip for ip in ips_from_file if ip]  # Use list comprehension to clean up empty lines
        total_to_process = len(unique_sorted_ips)
        logger.info(f"Total IPs to process (including duplicates/cached): {total_to_process}")

        with open(output_filepath, 'a', newline='', encoding='utf-8') as outfile:
            writer = None

            if header_written:
                # Use existing rows header
                writer = csv.DictWriter(outfile, fieldnames=existing_rows[0].keys(), extrasaction='ignore')

            for i, ip in enumerate(unique_sorted_ips):
                remaining = total_to_process - (i + 1)
                logger.info(f"Processing IP: {ip} ({i + 1}/{total_to_process})")

                # --- 1. Check CIDR Cache ---
                matched_cidr = is_ip_in_cached_networks(ip, cidr_cache)
                data = None  # This tracks if we made a NEW VPN API call

                if matched_cidr:
                    # Case A: Cache Hit (CIDR match)
                    # We are using the cached data. No API call needed.
                    logger.info(f"-> Using cached VPN API results for IP: {ip} (CIDR: {matched_cidr})")
                    flat_data = cidr_cache[matched_cidr].copy()
                else:
                    # Case B: Cache Miss (Need new lookup)
                    logger.info(f"-> Performing new VPN API lookup for {ip}...")
                    data = perform_lookup(ip, args.api_key, logger)  # API call made

                    if data:
                        flat_data = flatten_json(data)
                    else:
                        logger.warning(f"Skipping CSV write for IP {ip} due to failed VPN API lookup.")
                        continue  # Skip to the next IP

                if flat_data:
                    flat_data['ip'] = ip

                    geo_data = {field: "" for field in new_geo_fields}
                    lat_str = flat_data.get("location_latitude")
                    lng_str = flat_data.get("location_longitude")

                    # --- 2. Check Geo Cache ---
                    coord_key = None
                    if lat_str and lng_str:
                        try:
                            coord_key = (float(lat_str), float(lng_str))
                        except ValueError:
                            pass

                        if coord_key and coord_key in reverse_geocode_cache:
                            # Case C: Geocode Cache Hit
                            logger.info(f"-> Using cached geocode for coordinates: {lat_str}, {lng_str}")
                            geo_data = reverse_geocode_cache[coord_key]
                        elif coord_key:
                            # Case D: Geocode Cache Miss
                            logger.info(f"-> Performing new geocode lookup for: {lat_str}, {lng_str}")
                            geo_data = reverse_geocode_lookup(lat_str, lng_str, args.opencage_key, logger)
                            reverse_geocode_cache[coord_key] = geo_data  # Update Geo Cache

                    flat_data.update(geo_data)

                    # --- 3. CSV Writing & Cache Update (ALWAYS write the row) ---

                    # If the header hasn't been written, write it now based on the first processed flat_data
                    if not header_written:
                        original_header = list(flat_data.keys())
                        for field in new_geo_fields:
                            if field in original_header: original_header.remove(field)
                        final_header = original_header + new_geo_fields
                        writer = csv.DictWriter(outfile, fieldnames=final_header, extrasaction='ignore')
                        writer.writeheader()
                        header_written = True
                        logger.info("New CSV header written.")

                    # --- CHANGE 2: ALWAYS WRITE THE ROW ---
                    if writer:
                        writer.writerow(flat_data)
                        logger.info(f"Wrote data for IP {ip} to CSV.")

                    # Only update the CIDR cache if a NEW lookup was performed
                    if data and flat_data.get("network_network"):
                        cidr_cache[flat_data["network_network"]] = flat_data
                        logger.info(f"Updated CIDR cache with new data for network: {flat_data['network_network']}")


    except Exception as e:
        logger.critical(f"A critical and unexpected error occurred: {e}")
        sys.exit(1)

    logger.info("Process finished.")


if __name__ == "__main__":
    main()