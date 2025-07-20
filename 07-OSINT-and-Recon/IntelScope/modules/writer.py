import csv

def save_csv(data, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "email"])
        writer.writeheader()
        for row in data:
            writer.writerow(row)
