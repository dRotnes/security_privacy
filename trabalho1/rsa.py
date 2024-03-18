from os import urandom
import time
import numpy as np
import matplotlib.pyplot as plt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# def generate_random_file(filename, size):
#     with open(filename, 'wb') as f:
#         f.write(urandom(size))


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


def time_encryption_decryption(file_sizes, repetitions):
    encryption_times = []
    decryption_times = []

    print("------------ Number of samples: "+str(repetitions)+" ------------")
    
    for size in file_sizes:
        total_encryption_time = 0
        total_decryption_time = 0

        print("\n------------ Starting ------------")
        print("File size: " + str(size) + " bytes")
        for i in range(repetitions):
            data = urandom(size)
            private_key, public_key = generate_rsa_key_pair()
            
            print("\nFile: ", i)
            cipher_text, encryption_time = rsa_encrypt(data, public_key)
            total_encryption_time += encryption_time
            print("Total encryption time: ",total_encryption_time)

            plain_text, decryption_time = rsa_decrypt(cipher_text, private_key)
            total_decryption_time += decryption_time
            print("Total decryption time: ",total_decryption_time)
            
        avg_encryption_time = total_encryption_time / repetitions
        avg_decryption_time = total_decryption_time / repetitions

        print("\n------------ Ending ------------")
        
        encryption_times.append(avg_encryption_time)
        decryption_times.append(avg_decryption_time)

        print("Average encryption time: ", avg_encryption_time)
        print("Average decryption time: ", avg_decryption_time)
        
    return encryption_times, decryption_times


def plot_results(file_sizes, encryption_times_list, decryption_times_list, repetitions_list):
    fig, ax = plt.subplots()
    
    colors = ['blue', 'green', 'red']
    markers = ['o', 's', 'D']
    
    for i, (encryption_times, decryption_times, repetitions) in enumerate(zip(encryption_times_list, decryption_times_list, repetitions_list)):
        label = f'Enc/Dec Time ({repetitions} samples)'
        ax.plot(file_sizes, encryption_times, label=label, marker=markers[i], color=colors[i])
        ax.plot(file_sizes, decryption_times, marker=markers[i], color=colors[i])
    
    plt.xticks(file_sizes)  # Explicitly set x-axis ticks to file sizes
    
    plt.xlabel('File Size (bytes)')
    plt.ylabel('Time (seconds)')
    plt.title('RSA Algorithm: Encryption/Decryption Time vs File Size')
    plt.legend()
    plt.grid(True)
    plt.show()

# Rest of the code remains unchanged...


if __name__ == "__main__":
    file_sizes = [2, 4, 8, 16, 32, 64, 128]  # bytes
    
    # Define repetitions for each experiment
    repetitions_list = [20, 40, 60]

    # Collect encryption and decryption times for different repetitions
    encryption_times_list = []
    decryption_times_list = []
    print("Algorithm: RSA\n")
    for repetitions in repetitions_list:
        encryption_times, decryption_times = time_encryption_decryption(file_sizes, repetitions)
        encryption_times_list.append(encryption_times)
        decryption_times_list.append(decryption_times)

    # Plot results for all repetitions
    plot_results(file_sizes, encryption_times_list, decryption_times_list, repetitions_list)
