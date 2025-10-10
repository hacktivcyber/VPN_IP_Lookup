import argparse
import requests
import csv
import sys

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

def main():
    """
    Main function to parse arguments, read IPs, perform lookups, and write to CSV.
    """
    parser = argparse.ArgumentParser(
        description="Perform IP address lookups using the vpnapi.io service and save results to a CSV file.")
    parser.add_argument("-i", "--input-file", required=True, help="Path to the text file containing a list of IP addresses.")
    parser.add_argument("-a", "--api-key", required=True, help="Your API key for vpnapi.io.")
    # MODIFICATION: Add the required argument for the output CSV file
    parser.add_argument("-w", "--write-file", required=True, help="Path to the output CSV file where results will be written.")

    args = parser.parse_args()

    input_file = args.input_file
    api_key = args.api_key
    # MODIFICATION: Use the value from the new argument for the output file path
    output_file = args.write_file

    header_written = False

    print(f"Reading IP addresses from: {input_file}")
    # MODIFICATION: Print the output file path after the input file path
    print(f"CSV output will be written to: {output_file}")


    try:
        # Read all IPs from the input file into a list
        with open(input_file, 'r') as infile:
            ips = [line.strip() for line in infile if line.strip()]

        # Deduplicate using a set and then sort the list
        unique_sorted_ips = sorted(list(set(ips)))

        print(f"Found {len(ips)} total IP(s). Processing {len(unique_sorted_ips)} unique IP(s).")
        # Removed redundant print of "Writing results to: {output_file}"

        with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
            writer = None
            total_to_process = len(unique_sorted_ips)

            # Iterate over the unique, sorted list of IPs
            for i, ip in enumerate(unique_sorted_ips):
                remaining = total_to_process - (i + 1)
                print(f"Looking up: {ip}... ({remaining} IPs remaining)")
                data = perform_lookup(ip, api_key)

                if data:
                    # Flatten the nested JSON data
                    flat_data = flatten_json(data)

                    # On the first successful lookup, write the header row
                    if not header_written:
                        header = flat_data.keys()
                        writer = csv.DictWriter(outfile, fieldnames=header)
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