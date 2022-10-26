from hashlib import sha256
import string
from itertools import product

SALT = 'aB6nkeF0He3imq4AOhbO5kEljbveRpLn'


def list_from_txt(txt):
    list_txt = []
    with open(txt, encoding= 'utf-8', errors= 'ignore') as f:
          for line in f.readlines():
            list_txt.append(line.strip())
    return list_txt


def write_to_txt(txt, list_to_write):
    with open(txt, 'w',  encoding= 'utf-8', errors= 'ignore') as f:
        for item in list_to_write:
            f.write(f'{item}\n')


def write_dictionary_to_txt(txt, dictionary):
    with open(txt, 'w') as f:
        for key in dictionary:
            f.write(f'{key}:{dictionary[key]}\n')


def read_dictionary_from_txt(txt):
    dictionary = {}
    with open(txt, 'r') as f:
        for line in f.readlines():
            key, value = line.split(':')
            dictionary[key] = value
    return dictionary


def salt_and_hash(salt, key):
    return sha256((salt + key).encode('utf-8')).hexdigest()


def find_matched_hashes_in_global_hash_list(generated_hashes, global_hashes):
    return [value for value in generated_hashes if value in global_hashes]


def find_unhashed_value_from_hashed_using_unhashed_to_hashed_dictionary(hashed_value, unhashed_to_hashed_dictionary):
    return unhashed_to_hashed_dictionary[hashed_value]


def replace_chars_in_password(password, char_replace_dict):
    for char_being_replaced in char_replace_dict:
        password = password.replace(char_being_replaced, char_replace_dict[char_being_replaced])
    return password


CHAR_REPLACE_DICT = {
    'a': '@',
    'i': '1',
    'e': '3',
    'o': '0',
    'A': '@',
    'I': '1',
    'E': '3',
    'O': '0',
}


def generate_solution_dictionary(all_hashes, matched_hashes_dictionary):
    solution_dictionary = {}
    for hash in all_hashes:
        try:
            solution_dictionary[hash] = matched_hashes_dictionary[hash]
        except KeyError:
            solution_dictionary[hash] = ''
    return solution_dictionary


def find_if_password_in_hashes(password, hashes):
    hashed_password = salt_and_hash(SALT, password)
    if hashed_password in hashes:
        return hashed_password, password


def find_passwords_in_list(password_list, solution_dictionary, hashes):
    for password in password_list:
        matched_hash_and_password = find_if_password_in_hashes(password, hashes)
        if matched_hash_and_password:
            solution_dictionary[matched_hash_and_password[0]] = matched_hash_and_password[1]
            write_dictionary_to_txt('solution.txt',solution_dictionary)


def find_passwords_using_char_replacements(password_list, solution_dictionary, hashes):
    for item in password_list:
        changed_password = replace_chars_in_password(item, CHAR_REPLACE_DICT)
        matched_hash_and_password = find_if_password_in_hashes(changed_password, hashes)
        if matched_hash_and_password:
            solution_dictionary[matched_hash_and_password[0]] = matched_hash_and_password[1]
            write_dictionary_to_txt('solution.txt',solution_dictionary)


def generate_combination_passwords():
    characters = string.printable[:36]
    comb = []
    for i in range(1,5):
        comb += [''.join(i) for i in product(list(characters), repeat=i)]
    return comb


def generate_password_trailing_characters():
    characters = '0123456789!@#$%^&*-+=<>?'
    comb = []
    for i in range(1,4):
        comb += [''.join(i) for i in product(list(characters), repeat=i)]
    return comb


def generate_two_concatanated_words(common_words):
    return [''.join(word) for word in product(common_words, repeat=2)]


def generate_base_list():
    write_to_txt('base_list.txt', list_from_txt('rockyou.txt') +  generate_combination_passwords())


def find_passwords_from_common_words_and_trailing_characters(common_words_list, solution_dictionary, hashes):
    for item in common_words_list:
        for trailing_password_string in generate_password_trailing_characters():
            matched_hash_and_password = find_if_password_in_hashes(item + trailing_password_string, hashes)
            if matched_hash_and_password:
                solution_dictionary[matched_hash_and_password[0]] = matched_hash_and_password[1]
                write_dictionary_to_txt('solution.txt',solution_dictionary)


def generate_3_cases(word):
    cases = []
    cases.append(word.upper())
    cases.append(word.lower())
    cases.append(word.replace(word[0], word[0].upper()))
    return cases
    

def find_password_from_all_cases(word_list, solution_dictionary, hashes):
    for word in word_list:
        for each_case in generate_3_cases(word):
            matched_hash_and_password = find_if_password_in_hashes(each_case, hashes)
            if matched_hash_and_password:
                solution_dictionary[matched_hash_and_password[0]] = matched_hash_and_password[1]
                write_dictionary_to_txt('solution.txt',solution_dictionary)


if __name__ == "__main__":
    solution_dictionary = {}
    hashes = list_from_txt('hashes.txt')
    password_list = list_from_txt('base_list.txt')
    common_words_list_100k = list_from_txt('100k_common_words.txt')
    common_words_list_1k = list_from_txt('1k_common_words.txt')
    names = list_from_txt('names.txt')

    find_passwords_in_list(password_list, solution_dictionary, hashes)
    find_password_from_all_cases(names + common_words_list_100k, solution_dictionary, hashes)
    find_passwords_using_char_replacements(password_list, solution_dictionary, hashes)
    find_passwords_in_list(generate_two_concatanated_words(common_words_list_1k), solution_dictionary, hashes)
    find_passwords_from_common_words_and_trailing_characters(common_words_list_1k, solution_dictionary, hashes)

    print('length of matched hashes:' + str(len(solution_dictionary)))
    solution_dictionary = generate_solution_dictionary(hashes, solution_dictionary)
    write_dictionary_to_txt('cracked.txt', solution_dictionary)
