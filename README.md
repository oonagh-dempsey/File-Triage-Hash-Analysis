# File Triage & Hash Analysis

## Project Overview

This Python program performs basic cybersecurity file triage on a collection of sample files. It calculates SHA-256 hashes, compares them against a reference CSV, identifies duplicate files, and collects file metadata.

The program generates a text report containing the analysis results.

## Features

- Calculates SHA-256 hashes for sample files.
- Compares hashes against known reference values.
- Identifies files with identical hashes.
- Collects filenames, file sizes, extensions, and modification dates.
- Handles missing folders, missing reference files, and invalid CSV headings.
- Generates an analyst-friendly text report.

## Requirements

- Python 3
- No external Python packages required

## How to Run

1. Download or clone the repository.
2. Ensure the `samples` folder contains the sample files and `hashes_reference.csv`.
3. Open Command Prompt in the project directory.
4. Run:

   `python file_triage.py`

### Running with a Custom Folder

The program can also analyse a folder specified by the user.

To analyse the supplied samples folder, run:

`python file_triage.py samples`

To analyse another folder, replace `samples` with its folder path.

For example:

`python file_triage.py "C:\path\to\folder"`

The selected folder must contain a `hashes_reference.csv` file and the files to be analysed must currently have names beginning with `sample_`.

If the specified folder does not exist, the program displays an error message and exits.

5. View the results in Command Prompt.
6. Open `triage_report.txt` to view the generated report.

## Expected Results

The supplied dataset contains five sample files.

- Three files match known reference hashes.
- Two files have no reference match.
- `sample_a.txt` and `sample_b.txt` have identical SHA-256 hashes.

A missing reference match does not mean that a file is malicious.

## Error Handling

The program includes error handling for missing input folders, missing reference CSV files, invalid CSV headings, incomplete reference records, and file-reading errors.

## Limitations

SHA-256 hashes identify matching file contents but cannot independently determine whether a file is malicious. The reference comparison is limited to the hashes supplied in the CSV file.

## Output

The program generates `triage_report.txt`, containing file metadata, SHA-256 hashes, reference classifications, duplicate detection results, and analyst notes.
