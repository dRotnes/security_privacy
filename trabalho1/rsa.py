from os import urandom
import time
import numpy as np
import matplotlib.pyplot as plt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def rsa_encrypt(data, public_key):
    start_time = time.time()
    cipher_text = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    end_time = time.time()
    encryption_time = end_time - start_time
    return cipher_text, encryption_time


def rsa_decrypt(cipher_text, private_key):
    start_time = time.time()
    plain_text = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    end_time = time.time()
    decryption_time = end_time - start_time
    return plain_text, decryption_time


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def time_encryption_decryption(file_sizes, repetitions, log_file, private_key, public_key):
    encryption_times = []
    decryption_times = []

    log_file.write("------------ Number of samples: "+str(repetitions)+" ------------\n")

    # Turn public key into hexadecimal
    public_key_hex = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).hex()

    log_file.write("Public key: " + str(public_key_hex) + "\n")
    
    for size in file_sizes:
        total_encryption_time = 0
        total_decryption_time = 0

        log_file.write("\n------------ Starting ------------\n")
        log_file.write("File size: " + str(size) + " bytes\n")
        for i in range(repetitions):
            data = urandom(size)
            log_file.write("\nFile: " + str(i) + "\n")

            log_file.write("Data: "+str(data.hex()) + "\n")

            cipher_text, encryption_time = rsa_encrypt(data, public_key)
            total_encryption_time += encryption_time
            log_file.write("Encryption: " + str(cipher_text.hex()) + "\n")
            log_file.write("Total encryption time: " + str(total_encryption_time) + "\n")

            plain_text, decryption_time = rsa_decrypt(cipher_text, private_key)
            total_decryption_time += decryption_time
            log_file.write("Decryption: " + str(plain_text.hex())+ "\n")
            log_file.write("Total decryption time: " + str(total_decryption_time) + "\n")
            
        avg_encryption_time = total_encryption_time / repetitions
        avg_decryption_time = total_decryption_time / repetitions

        log_file.write("\n------------ Ending ------------\n")
        
        encryption_times.append(avg_encryption_time)
        decryption_times.append(avg_decryption_time)

        log_file.write("Average encryption time: " + str(avg_encryption_time) + "\n")
        log_file.write("Average decryption time: " + str(avg_decryption_time) + "\n")
        
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
    
    plt.xlabel('File Size (bytes)')
    plt.ylabel('Time (µs)')
    plt.title('RSA Algorithm: Encryption/Decryption Time vs File Size')
    plt.legend()
    plt.grid(True)
    plt.show()


if __name__ == "__main__":
    file_sizes = [2, 4, 8, 16, 32, 64, 128]  # bytes
    
    # Define repetitions for each experiment
    repetitions_list = [100,200]
    
    #Log file
    log_file = "rsa.log"

    # Generate key
    private_key, public_key = generate_rsa_key_pair()

    # Collect encryption and decryption times for different repetitions
    encryption_times_list = []
    decryption_times_list = []
    print("Algorithm: RSA")
    print("Generating plot and log file...")
    with open(log_file, 'w') as log_file:
        log_file.write("Algorithm: RSA\n")
        for repetitions in repetitions_list:
            encryption_times, decryption_times = time_encryption_decryption(file_sizes, repetitions, log_file, private_key, public_key)
            encryption_times_list.append(encryption_times)
            decryption_times_list.append(decryption_times)

    # Plot results for all repetitions
    plot_results(file_sizes, encryption_times_list, decryption_times_list, repetitions_list)
