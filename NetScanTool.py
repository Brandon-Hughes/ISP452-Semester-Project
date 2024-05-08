import nmap
import logging

logging.basicConfig(filename='nmap_scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    scanner = nmap.PortScanner()

    while True:
        ip_address = input("Enter the IP address to scan: ")
        try:
            response = scanner.scan(ip_address, arguments='-sn')
            if ip_address in response['scan']:
                logging.info(f"Valid IP address entered: {ip_address}")
                break
            else:
                logging.warning("IP address not reachable or invalid. User prompted to retry.")
                print("IP address not reachable or invalid. Please try again.")
        except nmap.PortScannerError:
            logging.error("Invalid IP address format entered. User prompted to retry.")
            print("Invalid IP address format. Please try again.")

    scan_type = handle_scan_selection()

    if scan_type != '-sn':
        ports = handle_port_selection()
        if ports!='':
            try:
                logging.info(f"Starting scan on IP: {ip_address} with ports: {ports} using scan type: {scan_type}")
                response = scanner.scan(ip_address, ports=ports, arguments=scan_type)
                print_scan_results(scanner)
            except nmap.PortScannerError as e:
                logging.error(f"nmap.PortScannerError occurred: {str(e)}")
                print(f"Error: {str(e)}")
            except Exception as e:
                logging.error(f"An unexpected error occurred: {str(e)}")
                print(f"An unexpected error occurred: {str(e)}")
        else:
            ports = ''
            try:
                logging.info(f"Starting scan on IP: {ip_address} with ports: {ports} using scan type: {scan_type}")
                response = scanner.scan(ip_address, arguments=scan_type)
                print_scan_results(scanner)
            except nmap.PortScannerError as e:
                logging.error(f"nmap.PortScannerError occurred: {str(e)}")
                print(f"Error: {str(e)}")
            except Exception as e:
                logging.error(f"An unexpected error occurred: {str(e)}")
                print(f"An unexpected error occurred: {str(e)}")
    else:
        ports = ''
        try:
            logging.info(f"Starting scan on IP: {ip_address} with ports: {ports} using scan type: {scan_type}")
            print_scan_results(scanner)
        except nmap.PortScannerError as e:
            logging.error(f"nmap.PortScannerError occurred: {str(e)}")
            print(f"Error: {str(e)}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {str(e)}")
            print(f"An unexpected error occurred: {str(e)}")

def handle_scan_selection():
    scan_types = {'1': '-sn', '2': '-sS', '3': '-sT', '4': '-sU', '5': '-sX'}
    while True:
        print("Please choose the type of scan you want to perform:")
        print("1. Ping Scan - Just checks if the host is up without scanning ports.")
        print("2. SYN Scan - Performs a quick stealth scan using TCP SYN packets.")
        print("3. TCP Scan - Completes the TCP handshake to check open ports.")
        print("4. UDP Scan - Completes the UDP handshake to check open ports.")
        print("5. Xmas Scan - Sets the FIN, PSH, and URG flags to gauge port status.")
        scan_choice = input("Enter your choice (1-5): ")

        if scan_choice in scan_types:
            return scan_types[scan_choice]
            logging.info(f"User selected scan type: {scan_choice}")
            break
        else:
            logging.warning("User made an invalid scan choice. Prompted to retry.")
            print("Invalid choice. Please enter 1 - 5.")

def handle_port_selection():
    while True:
        print("Do you want to scan specific ports?")
        print("1. No, scan all ports")
        print("2. Yes, scan a specific single port")
        print("3. Yes, scan a range of ports")
        port_choice = input("Enter your choice (1-3): ")

        if port_choice == '1':
            return ''
        elif port_choice == '2':
            return input("Enter the port number to scan: ")
        elif port_choice == '3':
            while True:
                port_start = input("Enter the start of the port range: ")
                port_end = input("Enter the end of the port range: ")
                if port_start.isdigit() and port_end.isdigit() and int(port_start) < int(port_end):
                    return f"{port_start}-{port_end}"
                else:
                    logging.warning("Invalid port range entered. User prompted to retry.")
                    print("Invalid port range. Start must be less than end and both must be numbers.")

def print_scan_results(scanner):
    logging.info("Scan results:")
    results = "Scan results:\n"
    for host in scanner.all_hosts():
        host_info = f"Host: {host} ({scanner[host].hostname()})\nState: {scanner[host].state()}\n"
        results += host_info
        logging.info(host_info)
        for proto in scanner[host].all_protocols():
            proto_info = f"Protocol: {proto}\n"
            results += proto_info
            logging.info(proto_info)
            lport = scanner[host][proto].keys()
            for port in lport:
                port_info = f"Port: {port}\tState: {scanner[host][proto][port]['state']}\tService: {scanner[host][proto][port]['name']}\n"
                results += port_info
                logging.info(port_info)
    print(results)

if __name__ == "__main__":
    main()
