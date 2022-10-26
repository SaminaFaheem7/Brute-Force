# Brute-Force
# How to Run this Program
This file contains all the functions needed to generate hashes and match them to passwords. You can import the functions for individual testing.
To run the entire program and generate all the matched passwords simply run `brute_force.py`. All the matched hashes will be outputted to `cracked.txt`, and hashes that were not found will have nothing next to them. The following text files are required to run the program:
- `rockyou.txt`: A list of common passwords.
- `1k_common_words.txt`: A list of common english words.
- `100k_common_words.txt`: A list of common english words.
- `base_list.txt`: Generated by this function, `generate_base_list` within the code.
- `names.txt`: A list of common english names.

# Parameters to change
The lists of passwords can be updated to include more names or more common passwords.
