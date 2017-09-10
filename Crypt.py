from random import randint
import hashlib
import io

pass_decrypt = "161ebd7d45089b3446ee4e0d86dbcf92"

# global rand
rand = randint(-5,5)
while rand == 0 or rand == 4:
    rand = randint(-5, 5)

# print("Your random: {}".format(rand))


def crypt_write(line, file):
    line = str(line)
    for c in line:
        try:
            if c != '\n':
                file.write('' + chr(ord(c) + rand))
            else:
                file.write('\n')
        except:
            pass

    return


def crypt_read(line, num):
    new_line = ""
    for i in range(len(line)):
        if line[i] != '\n':
            new_line += chr(ord(line[i]) - num)
    return new_line


def decrypt_file(file, num=rand):

    hasher = hashlib.md5()

    password = raw_input("Enter the password: ").strip()
    hasher.update(password)
    if hasher.hexdigest() != pass_decrypt:
        print("Invalid password! The file {} will remain undecrypted!".format(file))
        return


    file = open(file, "r")
    dec_str = ".Dec_{}".format(file.name)
    dec_file = open(dec_str, "w")
    new_line = ""
    for line in file:
        if line != '\n':
            new_line += crypt_read(line, num)

        else:
            new_line += '\n'

        dec_file.write("{}\n".format(new_line))
        new_line = ""
    dec_file.close()
    file.close()
    return


def hash_file(file):
    hasher = hashlib.md5()
    with io.open(file, mode='r', encoding='utf-8') as afile:
        try:
            buf = afile.read().encode('utf-8').strip()
            hasher.update(buf)
        except UnicodeDecodeError:
            pass
    return hasher.hexdigest()


def main():
    key = raw_input("Enter your decryption key: ")
    key = int(key)
    decrypt_file("Status_Log.txt", key)
    decrypt_file("ProcessList.txt", key)

    return

if __name__ == '__main__':

    main()

