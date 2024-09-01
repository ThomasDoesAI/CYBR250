import csv
from collections import defaultdict
from datetime import datetime

def analyze_log_file(file_path):
    """Analyze a log file produced by the firewall."""

    # Initialize counters and other variables
    domains = defaultdict(lambda: {'passes': 0, 'blocks': 0, 'bytes_in': 0, 'bytes_out': 0})
    total_entries = 0
    start_time = None
    end_time = None

    # Read the log file
    with open(file_path, 'r') as f:
        reader = csv.reader(f, delimiter='\t')
        next(reader)  # Skip the header row

        for row in reader:
            total_entries += 1
            timestamp, domain, bytes_in, bytes_out, flag, _ = row

            # Initialize start_time if this is the first row
            if start_time is None:
                start_time = timestamp
            end_time = timestamp

            # Convert flag to lowercase and map to correct dictionary key
            flag_key = 'passes' if flag.lower() == 'pass' else 'blocks' if flag.lower() == 'block' else None
            if flag_key:
                # Increment counters for this domain
                domains[domain][flag_key] += 1

            domains[domain]['bytes_in'] += int(bytes_in)
            domains[domain]['bytes_out'] += int(bytes_out)

    # Print the analysis report
    print('Log Analysis Report:')
    print(f'Total log entries: {total_entries}')
    print(f'Time range: {start_time} to {end_time}')

    # Print the top 10 domains by total connections
    print('\nTop 10 domains by total connections:')
    sorted_domains = sorted(domains.items(), key=lambda x: sum(x[1].values()), reverse=True)
    for domain, stats in sorted_domains[:10]:
        total = stats['passes'] + stats['blocks']
        print(f'{domain}: {total} connections ({stats["passes"]} passed, {stats["blocks"]} blocked)')
        print(f'  Data transfer: {stats["bytes_in"]} bytes in, {stats["bytes_out"]} bytes out')

    # Print domains with alternating PASS/BLOCK patterns
    print('\nDomains with alternating PASS/BLOCK patterns:')
    for domain, stats in domains.items():
        if stats['passes'] > 0 and stats['blocks'] > 0:
            print(f'{domain}: {stats["passes"]} passed, {stats["blocks"]} blocked')

if __name__ == "__main__":
    analyze_log_file('firewall_log.txt')
