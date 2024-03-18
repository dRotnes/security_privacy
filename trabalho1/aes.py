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

def time_encryption_decryption(file_sizes, repetitions, log_file, aesgcm):
    encryption_times = []
    decryption_times = []

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
        
    return encryption_times, decryption_times


def plot_results(file_sizes, encryption_times_list, decryption_times_list, repetitions_list):
    fig, ax = plt.subplots()
    
    colors = ['blue', 'green', 'red']
    markers = ['o', 's', 'D']
    
    for i, (encryption_times, decryption_times, repetitions) in enumerate(zip(encryption_times_list, decryption_times_list, repetitions_list)):
        label_enc = f'Encryption Time ({repetitions} samples)'
        label_dec = f'Decryption Time ({repetitions} samples)'
        
        # Convert time values to microseconds
        encryption_times_us = [t * 1e6 for t in encryption_times]
        decryption_times_us = [t * 1e6 for t in decryption_times]
        
        ax.plot(file_sizes, encryption_times_us, label=label_enc, marker=markers[i], color=colors[i])
        ax.plot(file_sizes, decryption_times_us, label=label_dec, linestyle='--', marker=markers[i], color=colors[i])
    
    ax.set_xscale('log', base=2)  # Use logarithmic scale for x-axis
    ax.set_xticks(file_sizes)     # Set x-axis ticks to file_sizes
    # ax.get_xaxis().set_major_formatter(ticker.ScalarFormatter())  # Show file sizes as tick labels
    
    plt.xlabel('File Size (bytes)')
    plt.ylabel('Time (µs)')
    plt.title('AES Algorithm: Encryption/Decryption Time vs File Size')
    plt.legend()
    plt.grid(True)
    plt.show()


if __name__ == "__main__":
    file_sizes = [8, 64, 512, 4096, 32768, 262144, 2097152]  # bytes
    
    # Define repetitions for each experiment
    repetitions_list = [5,10,15]

    # Log file
    log_file = "aes.log"

    # Generate key
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)

    # Collect encryption and decryption times for different repetitions
    encryption_times_list = []
    decryption_times_list = []
    print("Algorithm: AES")
    print("Generating plot and log file...")
    with open(log_file, 'w') as log_file:
        log_file.write("Algorithm: AES\n")
        for repetitions in repetitions_list:
            encryption_times, decryption_times = time_encryption_decryption(file_sizes, repetitions, log_file, aesgcm)
            encryption_times_list.append(encryption_times)
            decryption_times_list.append(decryption_times)

    # Plot results for all repetitions
    plot_results(file_sizes, encryption_times_list, decryption_times_list, repetitions_list)
