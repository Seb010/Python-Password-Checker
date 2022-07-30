# Getting the program to check that the password only contains allowed characters
# Uppercase A-Z
# Lowercase a-z
# Digits 0-9
# Symbols ! $ % ^ & * ( ) _ - + =
def is_password_with_allowed_chars(input):
    allowed_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!$%^&*()_-=+'
    for i in input:
        if i not in allowed_chars:
            return False
    return True


# Test tmp
# print("is_password_with_allowed_chars " + str(is_password_with_allowed_chars("fsi73 *")))


def find_lowercase_letter(input):
    result = False
    for i in input:
        if i.islower():
            result = True
    return result


def find_capital_letter(input):
    result = False
    for i in input:
        if i.isupper():
            result = True
    return result


def find_number_in_string(input):
    result = False
    for i in input:
        if i.isdigit():
            result = True
    return result


def find_symbol_in_string(input):
    result = False
    symbol = "!$%^&*()_-=+"
    for i in input:
        if i in symbol:
            result = True
    return result


def check_if_there_are_consecutive_upercase_letters(input):
    counter = 0
    for i in input:
        if counter == 3:
            return True
        if i.isupper():
            counter = counter + 1
        else:
            counter = 0
    if counter == 3:
        return True
    return False


def check_if_there_are_consecutive_lowercase_letters(input):
    counter = 0
    for i in input:
        if counter == 3:
            return True
        if i.islower():
            counter = counter + 1
        else:
            counter = 0
    if counter == 3:
        return True
    return False


def get_first_digit(input):
    for i in input:
        if i.isdigit():
            return i


def get_first_digit_index(input):
    index = 0
    for i in input:
        if i.isdigit():
            return index
        index = index + 1


def check_if_there_are_consecutive_numbers(input):
    if not find_number_in_string(input):
        return False
    counter = 1
    total_index = 0
    last_char = get_first_digit(input)
    last_char_index = get_first_digit_index(input)

    for i in input:
        if counter == 3:
            return True
        if i.isdigit():
            if int(i) - int(last_char) == 1 and total_index - last_char_index == 1:
                counter = counter + 1
            last_char = i
            last_char_index = total_index
        else:
            counter = 1
        total_index = total_index + 1
    if counter == 3:
        return True
    return False


def check_if_there_are_repetition_letters(input):
    counter = 0
    last_char = input[:1]

    for i in input:
        if counter == 3:
            return True
        if i.isalpha() and i == last_char:
            counter = counter + 1
        else:
            last_char = i
            counter = 1
    if counter == 3:
        return True
    return False

    # ASCII a-z 97-122 and A-Z 65-90
    # >>> ord('a')
    # 97
    # >>> chr(97)
    # 'a'
    # >>> chr(ord('a') + 3)
    # 'd'
    # >>>


def does_password_contain_letters_only(password):
    length = len(password)
    counter = 0
    for i in password:
        if (int(ord(i)) >= 97 and int(ord(i)) <= 122) or (int(ord(i)) >= 65 and int(ord(i)) <= 90):
            counter = counter + 1
    return length == counter


# ASCII 0-9 --> 45-57
#     print ("******************"+ str(ord('0')))
#     print ("******************"+ str(ord('9')))
def does_password_contain_digits_only(password):
    length = len(password)
    counter = 0
    for i in password:
        if (int(ord(i)) >= 45 and int(ord(i)) <= 57):
            counter = counter + 1
    return length == counter


def does_password_contain_symbols_only(password):
    symbols = "!$%^&*()_-=+"
    counter = 0
    length = len(password)
    for i in password:
        if i in symbols:
            counter = counter + 1
    return counter == length


def number_of_sets_3_consecutive_letters(password):
    return 1 # just for tests, implementation needed


def score_calculation(password):
    score = len(password)
    print("Initial score: " + str(score))
    if find_capital_letter(password):
        score = score + 5
        print("There is a capital letter. 5 points added ! Collected points:" + str(score))
    if find_lowercase_letter(password):
        score = score + 5
        print("There is a lowercase letter. 5 points added ! Collected points:" + str(score))
    if find_number_in_string(password):
        score = score + 5
        print("There is a digit. 5 points added ! Collected points:" + str(score))
    if find_symbol_in_string(password):
        score = score + 5
        print("There is a symbol. 5 points added ! Collected points:" + str(score))
    if find_capital_letter(password) and find_lowercase_letter(password) and find_number_in_string(
            password) and find_symbol_in_string(password):
        score = score + 10
        print(
            "Password contains at least one Lowercase Letters AND Uppercase Letters AND Number AND Symbol. 10 points added ! Collected points:" + str(
                score))
    # Points will be subtracted below -- place for ASCII implementation
    if does_password_contain_letters_only(password):
        score = score - 5
        print("Password contains letters only. 5 points taken away ! Collected points:" + str(score))
    if does_password_contain_digits_only(password):
        score = score - 5
        print("Password contains digits only. 5 points taken away ! Collected points:" + str(score))
    if does_password_contain_symbols_only(password):
        score = score - 5
        print("Password contains symbols only. 5 points taken away ! Collected points:" + str(score))
    # if the password contains 3 consecutive letters based on the layout of the UK QWERTY Keyboard then 5 points are
    # returns int of how many sets
    # subtract from the score for each set of 3
    if number_of_sets_3_consecutive_letters(password) > 0:
        for x in range(0, number_of_sets_3_consecutive_letters(password)):
            score = score - 5
            print(
                "Password contains a set of 3 consecutive letters (UK QWERTY Keyboard). 5 points taken away ! Collected points:" + str(
                    score))

    return score


def password_category_calculation(score):
    result = "medium"
    if score > 20:
        result = "strong"
    elif score < 0:
        result = "weak"
    return result


def CheckPassword():
    password = input("Enter a password")
    score = len(password)
    if len(password) > 20:
        print("Enter a smaller password")
    elif len(password) < 5:
        print("Enter a bigger password")
    else:
        print("Password consists of the allowed chars only: " + str(is_password_with_allowed_chars(password)))
        if is_password_with_allowed_chars(password):
            score_result = score_calculation(password)
            print("Total points: " + str(score_result))
            print("The password strength: " + str(password_category_calculation(score_result)))


def CheckCode(code):
    Uppercase = False
    Uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    for letters in Uppercase:
        if letters in code:
            Uppercase = True

    Lowercase = False
    Lowercase = 'abcdefghijklmnopqrstuvwxyz'
    for letters in Lowercase:
        if letters in code:
            Lowercase = True

    Number = False
    Number = '0123456789'
    for letters in Number:
        if letters in code:
            Number = True

    Symbol = False
    Symbol = '!$%^&*()_-=+'
    for letters in Symbol:
        if letters in code:
            Symbol = True


def MainMenu():
    print("1.  Press 1 to check the strength of a password")
    print("2,  Press 2 to generate a random password")
    print("3.  Press 3 to Quit")


while True:

    MainMenu()
    selection = input("Enter your choice")

    if selection == "1":
        CheckPassword()
    elif selection == "2":
        GeneratePassword()
    elif selection == "3":
        break
    else:
        print("Enter a valid option")
