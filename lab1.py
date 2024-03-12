def caesar_cipher(inumber:int, plain_text: str) -> str :
    if inumber > 25:
        return "Wrong input"
    
    lower_case_bound = [97,122]
    upper_case_bound = [65,90]
    
    cipher_text = ""

    for ch in plain_text:
        ch_num = ord(ch)
        if ch_num >=lower_case_bound[0] and ch_num<=lower_case_bound[1]:
            if(ch_num + inumber > lower_case_bound[1]):
                cipher_text+=chr(ch_num+inumber-26)
            else:
                cipher_text+=chr(ch_num+inumber)

        elif ch_num >=upper_case_bound[0] and ch_num<=upper_case_bound[1]:
            if(ch_num+inumber > upper_case_bound[1]):
                cipher_text+=chr(ch_num+inumber-26)
            else:
                cipher_text+=chr(ch_num+inumber)

        else:
            cipher_text += ch
     
    return cipher_text


def caesar_cipher_attack(cipher_text:str, keyword:str = None) -> dict:
    decryption_list = []

    lower_case_bound = [97,122]
    upper_case_bound = [65,90]

    for i in range(1,26):
        plain_text = ""
        for ch in cipher_text:
            ch_num = ord(ch)

            if ch_num >=lower_case_bound[0] and ch_num<=lower_case_bound[1]:
                if(ch_num - i < lower_case_bound[0]):
                    plain_text+=chr(ch_num-i+26)
                else:
                    plain_text+=chr(ch_num-i)
                    
            elif ch_num>=upper_case_bound[0] and ch_num<=upper_case_bound[1]:
                if(ch_num - i < upper_case_bound[0]):
                    plain_text+=chr(ch_num-i+26)
                else:
                    plain_text+=chr(ch_num-i)

            else:
                plain_text += ch

        if keyword != None:
            if keyword in plain_text:
                decryption_list.append((i, plain_text))
        else: 
            decryption_list.append((i, plain_text))

    return decryption_list

def letter_incidence_verification(cipher_text:str)-> list:

    different_letters = list(set(cipher_text))

    return sorted([(ch, cipher_text.count(ch)/len(cipher_text)) for ch in different_letters], key= lambda x: -x[1])


print(letter_incidence_verification("aksbbsbsbsjajansnsjaspo"))