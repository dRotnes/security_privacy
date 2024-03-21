from os import urandom
import time
import numpy as np
import matplotlib.pyplot as plt
from matplotlib import ticker
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def aes_encrypt(message: bytes, nonce: bytes, aesgcm) -> bytes:
    start_time = time.time()
    cipher_text = aesgcm.encrypt(nonce, message, None)
    end_time = time.time()
    encryption_time = end_time - start_time
    return cipher_text, encryption_time

def aes_decrypt(message: bytes, nonce: bytes, aesgcm) -> str:
    start_time = time.time()
    plain_text = aesgcm.decrypt(nonce, message, None)
    end_time = time.time()
    decryption_time = end_time - start_time
    return plain_text, decryption_time

def run_enc_dec_random(file_sizes, repetitions, log_file, aesgcm):
    encryption_times = []
    decryption_times = []

    print("------------ Random Files Test ------------\n")

    log_file.write(f"------------ Number of samples: {repetitions} ------------\n")

    for size in file_sizes:
        total_encryption_time = 0
        total_decryption_time = 0

        log_file.write(f"\n------------ Starting ------------\n")
        log_file.write(f"File size: {size} bytes\n")

        for i in range(repetitions):
            data = urandom(size)
            nonce = urandom(12)

            log_file.write("\nFile: " + str(i) + "\n")

            log_file.write("Data: "+str(data.hex()) + "\n")

            cipher_text, encryption_time = aes_encrypt(data, nonce, aesgcm)
            total_encryption_time += encryption_time
            log_file.write("Encryption: " + str(cipher_text.hex()) + "\n")
            log_file.write("Total encryption time: " + str(total_encryption_time) + "\n")

            plain_text, decryption_time = aes_decrypt(cipher_text, nonce, aesgcm)
            total_decryption_time += decryption_time
            log_file.write("Decryption: " + str(plain_text.hex())+ "\n")
            log_file.write("Total decryption time: " + str(total_decryption_time) + "\n")
            
        avg_encryption_time = total_encryption_time / repetitions
        avg_decryption_time = total_decryption_time / repetitions

        log_file.write(f"\n------------ Ending ------------\n")
        log_file.write(f"Average encryption time: {avg_encryption_time}\n")
        log_file.write(f"Average decryption time: {avg_decryption_time}\n\n")
        
        encryption_times.append(avg_encryption_time)
        decryption_times.append(avg_decryption_time)

        print(f"File size: {size} | Average encryption time: {avg_encryption_time} | Average decryption time: {avg_decryption_time}\n")

        
    return encryption_times, decryption_times

def run_enc_dec_same(file_sizes, repetitions, log_file, aesgcm):
    encryption_times = []
    decryption_times = []

    print("------------ Same Files Test ------------\n")

    log_file.write(f"------------ Number of samples: {repetitions} ------------\n")

    for size in file_sizes:
        total_encryption_time = 0
        total_decryption_time = 0

        log_file.write(f"\n------------ Starting ------------\n")
        log_file.write(f"File size: {size} bytes\n")

        data = urandom(size)
        for i in range(repetitions):
            nonce = urandom(12)

            log_file.write("\nFile: " + str(i) + "\n")

            log_file.write("Data: "+str(data.hex()) + "\n")

            cipher_text, encryption_time = aes_encrypt(data, nonce, aesgcm)
            total_encryption_time += encryption_time
            log_file.write("Encryption: " + str(cipher_text.hex()) + "\n")
            log_file.write("Total encryption time: " + str(total_encryption_time) + "\n")

            plain_text, decryption_time = aes_decrypt(cipher_text, nonce, aesgcm)
            total_decryption_time += decryption_time
            log_file.write("Decryption: " + str(plain_text.hex())+ "\n")
            log_file.write("Total decryption time: " + str(total_decryption_time) + "\n")
            log_file.write(f"Status: {str(plain_text.hex()) == str(data.hex())} \n")
            
        avg_encryption_time = total_encryption_time / repetitions
        avg_decryption_time = total_decryption_time / repetitions

        log_file.write(f"\n------------ Ending ------------\n")
        log_file.write(f"Average encryption time: {avg_encryption_time}\n")
        log_file.write(f"Average decryption time: {avg_decryption_time}\n\n")
        
        encryption_times.append(avg_encryption_time)
        decryption_times.append(avg_decryption_time)

        print(f"File size: {size} | Average encryption time: {avg_encryption_time} | Average decryption time: {avg_decryption_time}\n")
        
    return encryption_times, decryption_times



def plot_results(file_sizes, encryption_times_list, decryption_times_list, encryption_times_list_same, decryption_times_list_same, repetitions):
    fig, ax = plt.subplots()
    
    colors = ['blue', 'red']
    markers = ['o', 's']
    
    # Plot random files encryption and decryption
    ax.plot(file_sizes, [t * 1e6 for t in encryption_times_list], label='Random Files Encryption', marker=markers[0], color=colors[0])
    ax.plot(file_sizes, [t * 1e6 for t in decryption_times_list], label='Random Files Decryption', linestyle='--', marker=markers[0], color=colors[0])

    # Plot same file encryption and decryption
    ax.plot(file_sizes, [t * 1e6 for t in encryption_times_list_same], label='Same File Encryption', marker=markers[1], color=colors[1])
    ax.plot(file_sizes, [t * 1e6 for t in decryption_times_list_same], label='Same File Decryption', linestyle='--', marker=markers[1], color=colors[1])
    
    ax.set_xscale('log', base=2)  
    ax.set_xticks(file_sizes)     
    
    plt.xlabel('File Size (bytes)')
    plt.ylabel('Time (µs)')
    plt.title(f'AES Algorithm: Encryption/Decryption Time vs File Size ({repetitions} samples)')
    plt.legend()
    plt.grid(True)
    plt.show()



if __name__ == "__main__":
    file_sizes = [8, 64, 512, 4096, 32768, 262144, 2097152]  # bytes
    
     # Define repetitions for each experiment
    repetitions = 1000
    
    #Log file
    log_file = "aes.log"
    log_file_same = "aes_same.log"

    # Generate key
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)


    print("Algorithm: AES")
    print("Generating plot and log file...")
    print("\n-------------------------------------\n")


    with open(log_file, 'w') as log_file:
        log_file.write("Algorithm: AES\n")
        encryption_times, decryption_times = run_enc_dec_random(file_sizes, repetitions, log_file, aesgcm)
        
    with open(log_file_same, 'w') as log_file:
        log_file.write("Algorithm: AES\n")
        encryption_times_same, decryption_times_same = run_enc_dec_same(file_sizes, repetitions, log_file, aesgcm)

    # Plot results for all repetitions
    plot_results(file_sizes, encryption_times, decryption_times, encryption_times_same, decryption_times_same, repetitions)
