import re
import csv

class logParserAnalysis:
    def __init__(self):
        self.request_count = {}
        self.endpoint_access = {}
        self.failed_logins = {}
        self.THRESHOLD = 10
        self.CSV_FILENAME = "log_analysis_results.csv"
        self.FILENAME = "sample.log"

    def log_parser(self, file_name):
        with open(file_name, "r") as file:
            for line in file:
                # IP address count insert in request_count
                ip_address_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_address_match:
                    ip_address = ip_address_match.group(1)
                    if ip_address not in self.request_count:
                        self.request_count[ip_address] = 1
                    else:
                        self.request_count[ip_address] += 1

                # Count endpoint and store in endpoint_access
                endpoint_match = re.search(r'\"(GET|POST) (.+?) HTTP', line)
                if endpoint_match:
                    endpoint = endpoint_match.group(2)
                    if endpoint not in self.endpoint_access:
                        self.endpoint_access[endpoint] = 1
                    else:
                        self.endpoint_access[endpoint] += 1

                # Calculate failed logins
                if "401" in line and "Invalid credentials" in line:
                    ip_address_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_address_match:
                        ip_address = ip_address_match.group(1)
                        if ip_address not in self.failed_logins:
                            self.failed_logins[ip_address] = 1
                        else:
                            self.failed_logins[ip_address] += 1


    def count_requests_per_ip(self, request_count):
        request_count = dict(sorted(request_count.items(), key=lambda item: item[1], reverse=True))
        print("IP Address\tCount")
        for ip_addr, counts in request_count.items():
            print(f"{ip_addr}\t{counts}")
        return request_count

    def most_frequently_accessed_endpoint(self, endpoint_access):
        endpoint_access = dict(sorted(endpoint_access.items(), key=lambda item: item[1], reverse=True))
        print("Most frequently accessed endpoint:")
        endpoint = list(endpoint_access.keys())[0]
        count = endpoint_access[endpoint]
        print(f"{endpoint} (Accessed {count} times).")
        return endpoint, count

    def detect_suspicious_activity(self, failed_logins):
        if not failed_logins:
            print("No failed login attempts found.")
            return {}

        failed_logins = dict(sorted(failed_logins.items(), key=lambda item: item[1], reverse=True))
        logins = {}
        print("Suspicious Activity Detected:")
        print("IP Address\tFailed login attempts")
        suspicious_found = False

        for ip_address, count in failed_logins.items():
            if count > self.THRESHOLD:
                logins[ip_address] = count
                print(f"{ip_address}\t{count}")
                suspicious_found = True

        if not suspicious_found:
            print("No suspicious activity detected. All failed login attempts are below the threshold.")

        return logins

    def write_as_csv(self):
        self.log_parser(self.FILENAME)
        request_count = self.count_requests_per_ip(self.request_count)
        frequent_access_endpoint = self.most_frequently_accessed_endpoint(self.endpoint_access)
        detect_failed_logins = self.detect_suspicious_activity(self.failed_logins)

        # Write data to CSV file
        with open(self.CSV_FILENAME, 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)

            writer.writerow(["Request Count per IP"])
            writer.writerow(["IP Address","Request Count"])
            for ip_addr, counts in request_count.items():
                writer.writerow([ip_addr, counts])

            writer.writerow(["Most Frequently Accessed Endpoint"])
            writer.writerow(["Endpoint","Access Count"])
            writer.writerow([frequent_access_endpoint[0], frequent_access_endpoint[1]])

            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address","Failed Login Attempts"])
            for ip_address, count in detect_failed_logins.items():
                writer.writerow([ip_address, count])

if __name__ == "__main__":
    log_parser = logParserAnalysis()
    log_parser.write_as_csv()
