import re
import random
import hashlib

characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-='
password_length = random.randint(8, 12)

#external file of most commonly used passwords
with open('Most Common Passwords.txt') as list_of_passwords: 
    common_passwords = [line.strip() for line in list_of_passwords]

#converts the password into an MD5 hexadecimal representation 
def pw_to_md5(password):
    hash = hashlib.md5()
    hash.update(password.encode('utf-8'))
    pw_hash = hash.hexdigest()
    
    with open('Password_Recorder.txt', 'a') as password_record:
        password_record.write(pw_hash + '\n')

def auto_pw_question():
    while True:
        auto_pw_question = input('Would you like a randomly generated password? (Y/N) \n').upper()
        #checks if user wants to either have a generated one or create their own
        if auto_pw_question == 'N' or auto_pw_question == 'n':
            break
        elif auto_pw_question == 'Y' or auto_pw_question == 'y':
            password = ''.join(random.choices(characters, k=password_length))
            #will check if password contains at least one of each type of character and breaks once it does
            if any(char.islower() for char in password) and any(char.isupper() for char in password) and any(char.isdigit() for char in password) and any(not char.isalnum() for char in password):
                #converts the generated password into an MD5 hexadecimal format and stores it in a text file
                pw_to_md5(password)
                print(password)
                #ends the program
                exit()
            else:
                password = ''.join(random.choices(characters, k=password_length))

#checks if password is shorter than 8 characters
def check_password(password):
    if len(password) < 8: 
        return 'Password is too short'

    #checks if password is in the commonly used file
    if password in common_passwords:
        return 'Password is a commonly used password'
    #checks if password has an uppercase and lowercase
    if not re.search(r'[A-Z]', password):
        return 'Password must contain at least one uppercase letter'
    if not re.search(r'[a-z]', password):
        return 'Password must contain at least one lowercase letter'

    #checks if password has at least one digit
    if not re.search(r'\d', password):
        return 'Password must contain at least one digit'
    if not re.search(r'\W', password):
        return 'Password must contain at least one special character'
    
    else: 
        return 'Password is strong'

auto_pw_question()
password = input('Please create a password: \n')
check_password(password)

while True: 
    password_strength = check_password(password)
    if password_strength == 'Password is strong':
        print('Password is strong')
        #converts the user generated password into an MD5 hexadecimal format and stores it in a text file 
        pw_to_md5(password)
        break
    else: 
        print(password_strength)
        password = input('Please enter a stronger password: \n')