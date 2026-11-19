
from pathlib import Path
import hashlib
import csv
from datetime import datetime


samples_folder = Path(__file__).parent / "samples"

if samples_folder.exists():
    print("Samples folder found!")

    for file in samples_folder.iterdir():
        if file.is_file():
            print(file.name)
else:
    print("Error: Samples folder not found.")
    raise SystemExit(1)


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    except OSError as error:
        print(f"Error reading {file_path.name}: {error}")
        return None


print("\nSHA-256 Hash Results:")

for file in sorted(samples_folder.iterdir()):
    if file.name.startswith("sample_") and file.is_file():
        file_hash = calculate_sha256(file)
        if file_hash is not None:
            print(f"{file.name}: {file_hash}")
        else:
            print(f"{file.name}: HASH FAILED")



def load_reference_hashes(csv_path):
    reference_hashes = {}

    try:
        with open(csv_path, "r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames or not {"sha256", "label"}.issubset(reader.fieldnames):
                print("Error: Reference CSV has invalid column headings.")
                raise SystemExit(1)

            for row in reader:
                file_hash = row["sha256"]
                label = row["label"]

                if not file_hash or not label:
                    print("Error: Reference CSV contains incomplete data.")
                    raise SystemExit(1)

                reference_hashes[file_hash.strip().lower()] = label.strip()

    except OSError as error:
        print(f"Error loading reference CSV: {error}")
        raise SystemExit(1)

    return reference_hashes



reference_file = samples_folder / "hashes_reference.csv"
known_hashes = load_reference_hashes(reference_file)

print("\nReference Hash Comparison:")

for file in sorted(samples_folder.iterdir()):
    if file.name.startswith("sample_") and file.is_file():
        file_hash = calculate_sha256(file)

        if file_hash is None:
            print(f"{file.name}: HASH FAILED")
        elif file_hash in known_hashes:
            print(f"{file.name}: MATCH - {known_hashes[file_hash]}")
        else:
            print(f"{file.name}: NO MATCH")


def find_duplicates(folder):
    hash_groups = {}

    for file in sorted(folder.iterdir()):
        if file.is_file() and file.name.startswith("sample_"):
            file_hash = calculate_sha256(file)

            if file_hash is None:
                continue

            if file_hash not in hash_groups:
                hash_groups[file_hash] = []

            hash_groups[file_hash].append(file.name)

    return hash_groups


print("\nDuplicate File Detection:")

hash_groups = find_duplicates(samples_folder)
duplicates_found = False

for file_hash, filenames in hash_groups.items():
    if len(filenames) > 1:
        duplicates_found = True
        print(f"Duplicates found: {', '.join(filenames)}")

if not duplicates_found:
    print("No duplicate files found.")


def get_file_metadata(file_path):
    file_info = file_path.stat()

    return {
        "filename": file_path.name,
        "size": file_info.st_size,
        "extension": file_path.suffix,
        "modified": datetime.fromtimestamp(
            file_info.st_mtime
        ).strftime("%Y-%m-%d %H:%M:%S")
    }


print("\nFile Metadata:")

for file in sorted(samples_folder.iterdir()):
    if file.is_file() and file.name.startswith("sample_"):
        metadata = get_file_metadata(file)

        print(f"\nFilename: {metadata['filename']}")
        print(f"Size: {metadata['size']} bytes")
        print(f"Extension: {metadata['extension']}")
        print(f"Last Modified: {metadata['modified']}")




def generate_report(folder, known_hashes):
    report_path = Path(__file__).parent / "triage_report.txt"
    hash_groups = find_duplicates(folder)

    with open(report_path, "w", encoding="utf-8") as report:
        report.write("FILE TRIAGE & HASH ANALYSIS REPORT\n")
        report.write("=" * 45 + "\n\n")

        total_files = 0
        matched_files = 0
        unknown_files = 0

        for file in sorted(folder.iterdir()):
            if not file.is_file() or not file.name.startswith("sample_"):
                continue

            total_files += 1
            file_hash = calculate_sha256(file)

            try:
                metadata = get_file_metadata(file)
            except OSError as error:
                report.write(f"{file.name}: ERROR - {error}\n\n")
                continue

            if file_hash is None:
                status = "ERROR - Unable to calculate hash"
            elif file_hash in known_hashes:
                status = f"KNOWN - {known_hashes[file_hash]}"
                matched_files += 1
            else:
                status = "UNKNOWN - No reference match"
                unknown_files += 1

            report.write(f"Filename: {metadata['filename']}\n")
            report.write(f"Extension: {metadata['extension']}\n")
            report.write(f"Size: {metadata['size']} bytes\n")
            report.write(f"Modified: {metadata['modified']}\n")
            report.write(f"SHA-256: {file_hash or 'Unavailable'}\n")
            report.write(f"Status: {status}\n\n")

        report.write("SUMMARY\n")
        report.write("-" * 45 + "\n")
        report.write(f"Files processed: {total_files}\n")
        report.write(f"Known reference matches: {matched_files}\n")
        report.write(f"Unknown files: {unknown_files}\n\n")

        report.write("DUPLICATE FILES\n")
        report.write("-" * 45 + "\n")

        duplicate_count = 0

        for file_hash, filenames in hash_groups.items():
            if len(filenames) > 1:
                duplicate_count += 1
                report.write(f"SHA-256: {file_hash}\n")
                report.write(f"Files: {', '.join(filenames)}\n\n")

        if duplicate_count == 0:
            report.write("No duplicates found.\n")

        report.write("\nANALYST NOTES\n")
        report.write("A reference match identifies identical file content.\n")
        report.write("An unknown hash does not prove that a file is malicious.\n")
        report.write("Hash analysis alone cannot determine file behaviour.\n")

    print(f"\nReport saved successfully: {report_path.name}")


generate_report(samples_folder, known_hashes)

